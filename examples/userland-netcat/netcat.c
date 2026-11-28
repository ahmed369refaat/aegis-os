/* P1-1: the first NETWORK userland citizen — a gcc freestanding
 * static binary that opens sockets, exchanges data, and closes them
 * through the P1-1 sockets surface (the byte-channel marshaller over
 * the ring-3 tcpip service), WITHOUT any network syscall of its own:
 * the profile's mask answers SYS_NET_SEND/SYS_NET_RECV with -EPERM
 * (denied by policy), which the program proves first, live, before
 * its first request.
 *
 * Built exactly like userland-hello (gcc -ffreestanding -nostdlib
 * -mgeneral-regs-only — this kernel's ring 3 has NO FPU/SSE state,
 * and -O2 zeroes structs with pxor/movaps unless that flag is set),
 * linked at the canonical cage's vaddrs (see netcat.ld), spawned by
 * the kernel's drvstack::tcpip step via spawn_user_elf under the
 * CANONICAL contract and the net-client profile.
 *
 * The protocol is the netsock wire: a 16-byte request header
 * {op u8, flags u8, kind u8, rsv u8, fd i32, ip [4], port u16,
 * len u16} (little-endian; only SEND carries a body), a 12-byte reply
 * header {op u8, rsv [3], result i32, len u32} (only RECV carries a
 * body). Strict lockstep: one request, park in recv_wait for its
 * reply, drain, repeat.
 *
 * Data page (the kernel patches 0x403800 before launch; the program
 * writes 0x403C00 for the kernel to verify after exit):
 *   0x403800  u32 magic 0x4E433031 "NC01"
 *   0x403808  u64 req_ch   the request pipe (service-owned)
 *   0x403810  u64 rep_ch   the reply pipe (this domain's own)
 *   0x403818  u8[4] peer   the echo peer (10.0.2.2, the slirp host)
 *   0x40381C  u16 tcp_port / u16 udp_port
 *   0x403C00  the report block (step, probes, flags, byte counts)
 */

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long  u64;
typedef long           i64;

/* ── the raw syscall ABI (internal op numbers — the spawned-domain
 * ABI: nr in RAX, args in RDI/RSI/RDX, result in RAX, -errno on
 * error) ── */
static inline i64 sys3(i64 nr, i64 a, i64 b, i64 c)
{
    i64 ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(nr), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return ret;
}

#define SYS_NET_SEND      9
#define SYS_NET_RECV      10
#define SYS_IPC_RECV_WAIT 27
#define SYS_PIPE_READ     30
#define SYS_PIPE_WRITE    31
#define SYS_EXIT          63

#define OP_SOCKET 1
#define OP_BIND   2
#define OP_LISTEN 3
#define OP_CONNECT 4
#define OP_ACCEPT 5
#define OP_SEND   6
#define OP_RECV   7
#define OP_CLOSE  8
#define OP_DONE   9

#define SOCK_STREAM 1
#define SOCK_DGRAM  2

#define REQ_HDR_LEN 16
#define REP_HDR_LEN 12

/* The kernel-patched config block (read volatile: the bytes change
 * after the link — see the tcpip service's module doc for why). */
struct nc_cfg {
    volatile u32 magic;
    u32 pad0;
    volatile u64 req_ch;
    volatile u64 rep_ch;
    volatile u8 peer[4];
    volatile u16 tcp_port;
    volatile u16 udp_port;
};

/* The report block the kernel verifies after exit. */
struct nc_rep {
    volatile u32 magic;      /* 0x4E435231 "NCR1", written at exit */
    volatile u32 step;       /* the last completed step (0 = clean) */
    volatile i64 probe_send; /* raw SYS_NET_SEND(buf,8) (expect -1 EPERM) */
    volatile i64 probe_recv; /* raw SYS_NET_RECV(buf,8) (expect -1 EPERM) */
    volatile u32 ops;        /* ops that round-tripped 0 */
    volatile u32 tcp_ok;
    volatile u32 udp_ok;
    volatile u32 bytes_out;
    volatile u32 bytes_in;
};

static struct nc_cfg *const CFG = (struct nc_cfg *)0x403800;
static struct nc_rep *const REP = (struct nc_rep *)0x403C00;

/* gcc's freestanding contract: it may still call these two. */
void *memcpy(void *d, const void *s, unsigned long n)
{
    u8 *dd = (u8 *)d;
    const u8 *ss = (const u8 *)s;
    for (unsigned long i = 0; i < n; i++)
        dd[i] = ss[i];
    return d;
}
void *memset(void *d, int c, unsigned long n)
{
    u8 *dd = (u8 *)d;
    for (unsigned long i = 0; i < n; i++)
        dd[i] = (u8)c;
    return d;
}

static void put16(u8 *p, u16 v) { p[0] = (u8)v; p[1] = (u8)(v >> 8); }
static void put32(u8 *p, u32 v)
{
    p[0] = (u8)v; p[1] = (u8)(v >> 8); p[2] = (u8)(v >> 16); p[3] = (u8)(v >> 24);
}
static i64 le32s(const u8 *p)
{
    return (i64)((u32)(p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24)));
}

static void die(u32 step, i64 code) __attribute__((noreturn));
static void die(u32 step, i64 code)
{
    REP->step = step;
    __asm__ volatile("mov $63, %%eax\n\t"
                     "mov %0, %%edi\n\t"
                     "syscall\n\t"
                     :
                     : "r"((u32)code)
                     : "eax", "edi", "memory");
    __builtin_unreachable();
}

/* One lockstep exchange: write the request, park for the reply, drain
 * it whole. `rep` holds the reply frame on return; the function
 * answers the reply's result field. */
static i64 ask(const u8 *req, u32 reqlen, u8 *rep, u32 repcap)
{
    i64 w = sys3(SYS_PIPE_WRITE, (i64)CFG->req_ch, (i64)req, (i64)reqlen);
    if (w != (i64)reqlen)
        return -1000; /* a short or refused request write */
    i64 woke = sys3(SYS_IPC_RECV_WAIT, (i64)CFG->rep_ch, 0, 0);
    if (woke < 0)
        return -1001; /* the rendezvous itself refused */
    i64 n = sys3(SYS_PIPE_READ, (i64)CFG->rep_ch, (i64)rep, (i64)repcap);
    if (n < REP_HDR_LEN)
        return -1002; /* not even a header */
    u32 len = (u32)le32s(rep + 8);
    if (n != (i64)(REP_HDR_LEN + (i64)len))
        return -1003; /* a partial or glued reply: refuse, fail closed */
    return le32s(rep + 4);
}

static u8 reqb[REQ_HDR_LEN + 64];
static u8 repb[REP_HDR_LEN + 512];

/* The ops, each a strict lockstep request. */
static i64 op_socket(u8 kind)
{
    u8 *r = reqb;
    for (u32 i = 0; i < REQ_HDR_LEN; i++)
        r[i] = 0;
    r[0] = OP_SOCKET;
    r[2] = kind;
    return ask(r, REQ_HDR_LEN, repb, sizeof(repb));
}

static i64 op_connect(i64 fd, const volatile u8 *ip, u16 port)
{
    u8 *r = reqb;
    for (u32 i = 0; i < REQ_HDR_LEN; i++)
        r[i] = 0;
    r[0] = OP_CONNECT;
    put32(r + 4, (u32)fd);
    for (u32 i = 0; i < 4; i++)
        r[8 + i] = ip[i];
    put16(r + 12, port);
    return ask(r, REQ_HDR_LEN, repb, sizeof(repb));
}

static i64 op_send(i64 fd, const char *payload, u32 len)
{
    u8 *r = reqb;
    for (u32 i = 0; i < REQ_HDR_LEN + len; i++)
        r[i] = 0;
    r[0] = OP_SEND;
    put32(r + 4, (u32)fd);
    put16(r + 14, (u16)len);
    for (u32 i = 0; i < len; i++)
        r[REQ_HDR_LEN + i] = (u8)payload[i];
    return ask(r, REQ_HDR_LEN + len, repb, sizeof(repb));
}

/* Blocking recv: the reply carries the payload; returns the count,
 * the bytes land in `out`. */
static i64 op_recv(i64 fd, u8 *out, u32 cap)
{
    u8 *r = reqb;
    for (u32 i = 0; i < REQ_HDR_LEN; i++)
        r[i] = 0;
    r[0] = OP_RECV;
    put32(r + 4, (u32)fd);
    put16(r + 14, (u16)cap);
    i64 res = ask(r, REQ_HDR_LEN, repb, sizeof(repb));
    if (res < 0)
        return res;
    u32 len = (u32)le32s(repb + 8);
    if (len > cap)
        len = cap;
    for (u32 i = 0; i < len; i++)
        out[i] = repb[REP_HDR_LEN + i];
    return (i64)len;
}

static i64 op_close(i64 fd)
{
    u8 *r = reqb;
    for (u32 i = 0; i < REQ_HDR_LEN; i++)
        r[i] = 0;
    r[0] = OP_CLOSE;
    put32(r + 4, (u32)fd);
    return ask(r, REQ_HDR_LEN, repb, sizeof(repb));
}

static i64 op_done(void)
{
    u8 *r = reqb;
    for (u32 i = 0; i < REQ_HDR_LEN; i++)
        r[i] = 0;
    r[0] = OP_DONE;
    return ask(r, REQ_HDR_LEN, repb, sizeof(repb));
}

static int same(const char *a, const u8 *b, u32 n)
{
    for (u32 i = 0; i < n; i++)
        if ((u8)a[i] != b[i])
            return 0;
    return 1;
}

void _start(void)
{
    static const char tcp_msg[] = "NETCAT-AEGIS-TCP"; /* 16 bytes */
    static const char udp_msg[] = "UDPPROBE99";       /* 10 bytes */
    u8 echo[64];
    i64 fd, r;

    /* 1. The honesty probes FIRST: a net-client domain must NOT be
     * able to bypass the broker — the mask answers both net syscalls
     * with -EPERM (denied by policy) before any capability is read. */
    REP->probe_send = sys3(SYS_NET_SEND, (i64)reqb, 8, 0);
    REP->probe_recv = sys3(SYS_NET_RECV, (i64)reqb, 8, 0);
    if (REP->probe_send != -1 || REP->probe_recv != -1)
        die(1, 96);

    /* 2. TCP: socket, connect, send, recv the echo, close. */
    fd = op_socket(SOCK_STREAM);
    if (fd < 0)
        die(2, 91);
    REP->ops++;
    r = op_connect(fd, CFG->peer, CFG->tcp_port);
    if (r != 0)
        die(3, 92);
    REP->ops++;
    r = op_send(fd, tcp_msg, 16);
    if (r != 16)
        die(4, 93);
    REP->ops++;
    REP->bytes_out += 16;
    r = op_recv(fd, echo, sizeof(echo));
    if (r != 16 || !same(tcp_msg, echo, 16))
        die(5, 94);
    REP->ops++;
    REP->bytes_in += 16;
    r = op_close(fd);
    if (r != 0)
        die(6, 95);
    REP->ops++;
    REP->tcp_ok = 1;
    REP->step = 6;

    /* 3. UDP: the same round trip over a connected datagram socket. */
    fd = op_socket(SOCK_DGRAM);
    if (fd < 0)
        die(7, 91);
    REP->ops++;
    r = op_connect(fd, CFG->peer, CFG->udp_port);
    if (r != 0)
        die(8, 92);
    REP->ops++;
    r = op_send(fd, udp_msg, 10);
    if (r != 10)
        die(9, 93);
    REP->ops++;
    REP->bytes_out += 10;
    r = op_recv(fd, echo, sizeof(echo));
    if (r != 10 || !same(udp_msg, echo, 10))
        die(10, 94);
    REP->ops++;
    REP->bytes_in += 10;
    r = op_close(fd);
    if (r != 0)
        die(11, 95);
    REP->ops++;
    REP->udp_ok = 1;
    REP->step = 11;

    /* 4. DONE: the service acks and closes every fd this client
     * still owns (nothing, by construction — the closes above ran). */
    r = op_done();
    if (r != 0)
        die(12, 97);
    REP->ops++;
    REP->step = 0;
    REP->magic = 0x4E435231u; /* "NCR1" */

    __asm__ volatile("mov $63, %%eax\n\t"
                     "xor %%edi, %%edi\n\t"
                     "syscall\n\t"
                     :
                     :
                     : "eax", "edi", "memory");
    __builtin_unreachable();
}
