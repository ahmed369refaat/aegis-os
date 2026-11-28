//! The tcpip service (P1-1): the ring-3 home of the policy core's
//! `netstack`, wired to the wire through the broker and nothing else.
//!
//! Egress has exactly one exit: [`netsock::BrokerQueue`] over
//! [`sys::net_send`] — `SYS_NET_SEND`, the kernel's policy gate (the
//! domain's Device cap + the token bucket) and the broker-mapped
//! virtio rings. Ingress has exactly one entrance: `SYS_NET_RECV`.
//! The service never touches a virtio ring, a device register, or a
//! DMA buffer; it has no DEVREG, no mmap, no file I/O (see the
//! `tcpip` profile — the mask answers every other door with -EPERM).
//!
//! Clients (any ring-3 domain the supervisor wired channels for)
//! speak the 16-byte request / 12-byte reply protocol of
//! [`aegis_os::netsock`] over two byte channels per client: requests
//! on the pipe the service owns, replies on the pipe the client
//! owns. Lockstep is the framing: a client sends one request and
//! parks in `recv_wait` for its reply — so at most one request frame
//! is ever in flight and the stage never sees glued frames (a client
//! that breaks lockstep loses: its glued frame answers one -EINVAL,
//! exactly as the host suite proves).
//!
//! The run model — the service NEVER parks:
//! `NET_RECV (non-blocking) → stack.poll(now) → recheck → reply
//! pipe_write → request pipe_read → SCHED_YIELD`, forever. It exits 0
//! once every expected client sent DONE and a bounded drain ran
//! (FIN/TIME_WAIT tails get to finish), non-zero on the idle
//! deadline. A park would be a deadlock the moment a client exits
//! first; a poll loop cannot deadlock.
//!
//! The kernel patches the config block (`.netcfg.config`, 0x420000)
//! before the first instruction runs and verifies the report block
//! (`.netcfg.report`, 0x420400) after exit — the field offsets are
//! pinned on both sides by `drvstack/tcpip.rs` and this module's
//! `repr(C)` order.
#![no_std]

use aegis_os::netsock::{self, BrokerQueue, Rep, Stage, Step, MAX_CLIENTS, OP_DONE};
use aegis_os::netstack::{Entropy, IfCfg, MacAddr, NetStack};

/// The shared page's two blocks (mirrored by the kernel's
/// `drvstack/tcpip.rs`; `tcpipd.ld` pins the addresses).
pub mod svc {
    /// The config block's page.
    pub const CONFIG_VA: u64 = 0x420_000;
    /// The report block (same page, second block).
    pub const REPORT_VA: u64 = 0x420_400;
    /// `"TCP1"` — the kernel writes it; a wrong value is a spawn bug.
    pub const CONFIG_MAGIC: u32 = 0x5443_5031;
    /// `"REP1"` — the service writes it at exit.
    pub const REPORT_MAGIC: u32 = 0x5245_5031;
}

/// The kernel-patched boot configuration (one `repr(C)` block, the
/// field order pinned on both sides — see `drvstack/tcpip.rs`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub magic: u32,
    pub client_count: u32,
    /// Request pipes, one per client slot (the service owns each).
    pub req_ch: [u64; MAX_CLIENTS],
    /// Reply pipes, one per client slot (client i owns rep_ch[i]).
    pub rep_ch: [u64; MAX_CLIENTS],
    pub mac: [u8; 6],
    pub _pad: [u8; 2],
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
    /// The peer the lane's client connects to (the slirp gateway,
    /// 10.0.2.2 — the host's echo servers).
    pub peer_ip: [u8; 4],
    pub tcp_port: u16,
    pub udp_port: u16,
    pub seed: u64,
    /// Idle deadline: no request, no frame, no live socket for this
    /// many milliseconds → the loud non-zero exit.
    pub idle_ms: u64,
    /// The post-DONE drain window (FIN/TIME_WAIT tails get to run).
    pub drain_ms: u64,
}

impl Config {
    /// The block's zero shape in the image; the kernel overwrites
    /// every field before launch.
    pub const EMPTY: Config = Config {
        magic: 0,
        client_count: 0,
        req_ch: [0; MAX_CLIENTS],
        rep_ch: [0; MAX_CLIENTS],
        mac: [0; 6],
        _pad: [0; 2],
        ip: [0; 4],
        netmask: [0; 4],
        gateway: [0; 4],
        peer_ip: [0; 4],
        tcp_port: 0,
        udp_port: 0,
        seed: 0,
        idle_ms: 0,
        drain_ms: 0,
    };
}

/// The report block the kernel verifies after exit.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Report {
    pub magic: u32,
    /// bit0 tcp round trip, bit1 udp round trip, bit2 the bucket
    /// refill, bit3 the EMSGSIZE probe.
    pub flags: u32,
    pub exit_code: i32,
    pub requests: u32,
    pub replies: u32,
    pub malformed: u32,
    pub timeouts: u32,
    pub cancelled: u32,
    pub tcp_sent: u32,
    pub tcp_recvd: u32,
    pub udp_sent: u32,
    pub udp_recvd: u32,
    /// The raw `NET_SEND(buf, 1515)` return (expect -90).
    pub emsgsize: i32,
    /// 1 when the bucket's EAGAIN was observed (the limit is real).
    pub throttle_seen: u32,
    /// 1 when a send succeeded after the 1.1 s wait (the refill is
    /// real — the kernel clock moved).
    pub refill_ok: u32,
    pub polls: u32,
    pub recvs: u32,
    pub frames_in: u32,
    pub frames_out: u32,
    pub live_socks: u32,
}

impl Report {
    pub const EMPTY: Report = Report {
        magic: 0,
        flags: 0,
        exit_code: 0,
        requests: 0,
        replies: 0,
        malformed: 0,
        timeouts: 0,
        cancelled: 0,
        tcp_sent: 0,
        tcp_recvd: 0,
        udp_sent: 0,
        udp_recvd: 0,
        emsgsize: 0,
        throttle_seen: 0,
        refill_ok: 0,
        polls: 0,
        recvs: 0,
        frames_in: 0,
        frames_out: 0,
        live_socks: 0,
    };

    /// flag bit helpers (the kernel reads the same bits).
    pub const F_TCP: u32 = 1;
    pub const F_UDP: u32 = 2;
    pub const F_REFILL: u32 = 4;
    pub const F_EMSGSIZE: u32 = 8;
}

/// The kernel-patched config block: `tcpipd.ld` pins this static at
/// 0x420000, inside the image's own data segment. The static exists
/// to PLACE and size the page — it is never read through the symbol:
/// the kernel overwrites the bytes after the link, so every read goes
/// through `read_volatile` at the pinned address (a plain read would
/// let LTO fold the image's const-zero bytes into the code — measured:
/// the whole service collapsed to `exit(2)` before this rule).
#[link_section = ".netcfg.config"]
#[used]
static CONFIG_PLACEHOLDER: Config = Config::EMPTY;

/// The report block's placeholder (pinned at 0x420400; likewise only
/// a placement marker — the write goes through the address).
#[link_section = ".netcfg.report"]
#[used]
static REPORT_PLACEHOLDER: Report = Report::EMPTY;

/// The kernel-patched config, read whole through one volatile load.
///
/// SAFETY: the block is this image's own data segment, aligned and
/// fully inside one mapped page; the kernel wrote every field before
/// the first instruction of this image ran (the spawn path's patch).
fn read_config() -> Config {
    unsafe { core::ptr::read_volatile(svc::CONFIG_VA as *const Config) }
}

/// Write the report block through one volatile store.
///
/// SAFETY: same page, same ownership; written once at exit, after
/// every other use of the service state has ended.
fn write_report(rep: &Report) {
    unsafe { core::ptr::write_volatile(svc::REPORT_VA as *mut Report, *rep) }
}

/// The raw syscall ABI (internal op numbers — the spawned-domain ABI):
/// nr in RAX, args in RDI/RSI/RDX, result in RAX (`-errno` on error).
pub mod sys {
    use core::arch::asm;

    #[inline(always)]
    fn sys3(nr: u64, a: u64, b: u64, c: u64) -> i64 {
        let ret;
        // SAFETY: the one instruction a ring-3 domain is allowed to
        // execute against the kernel; the instruction itself touches
        // no memory.
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") nr => ret,
                in("rdi") a,
                in("rsi") b,
                in("rdx") c,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack)
            );
        }
        ret
    }

    /// SYS_NET_SEND — the ONLY egress.
    pub fn net_send(buf: *const u8, len: u64) -> i64 {
        sys3(9, buf as u64, len, 0)
    }

    /// SYS_NET_RECV — the ONLY ingress (non-blocking flavor).
    pub fn net_recv(buf: *mut u8, len: u64) -> i64 {
        sys3(10, buf as u64, len, 0)
    }

    /// SYS_PIPE_READ — drain this service's request pipe (owner op).
    pub fn pipe_read(ch: u64, buf: *mut u8, len: u64) -> i64 {
        sys3(30, ch, buf as u64, len)
    }

    /// SYS_PIPE_WRITE — answer a reply on the client's pipe.
    pub fn pipe_write(ch: u64, buf: *const u8, len: u64) -> i64 {
        sys3(31, ch, buf as u64, len)
    }

    /// SYS_SCHED_YIELD — fairness AND the kernel-clock stamp (the
    /// bucket's refill windows ride it).
    pub fn sched_yield() -> i64 {
        sys3(22, 0, 0, 0)
    }

    /// SYS_CLOCK_GETTIME — the stack's monotonic time source.
    pub fn now_ms() -> u64 {
        let mut ts = [0u8; 16];
        if sys3(23, 0, ts.as_mut_ptr() as u64, 16) != 0 {
            return 0; // a refused clock reads as t0 — timers stall, loudly
        }
        let sec = u64::from_le_bytes(ts[..8].try_into().unwrap());
        let nsec = u64::from_le_bytes(ts[8..].try_into().unwrap());
        sec.saturating_mul(1000) + nsec / 1_000_000
    }

    /// SYS_EXIT.
    pub fn exit(code: i64) -> ! {
        let _ = sys3(63, code as u64, 0, 0);
        // The kernel never returns from EXIT; this only silences the
        // type system (spin, not halt: the halt path is the kernel's).
        loop {
            core::hint::spin_loop()
        }
    }
}

/// The service's one entropy source: a seeded xorshift, seeded by the
/// kernel per boot (documented deterministic — the ISN stream is
/// reproducible for a given seed, which is exactly what a lane wants).
pub struct XorShift(u64);

impl Entropy for XorShift {
    fn next_u32(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 as u32
    }
}

/// The wire: the BrokerQueue's one exit, the brokered syscall itself.
struct NetWire;

impl netsock::Wire for NetWire {
    fn transmit(&mut self, frame: &[u8]) -> Result<(), netsock::WireErr> {
        let r = sys::net_send(frame.as_ptr(), frame.len() as u64);
        match r {
            n if n >= 0 => Ok(()),
            -11 => Err(netsock::WireErr::Throttled), // EAGAIN: retry later
            -90 => Err(netsock::WireErr::TooLong),   // EMSGSIZE: never fits
            _ => Err(netsock::WireErr::Refused),     // the session is gone
        }
    }
}

/// The image's entry body: read the config, run, write the report,
/// answer the exit code. Returns the code for `_start` to deliver.
pub fn service_main() -> i32 {
    let cfg = read_config();
    let cfg = &cfg;
    let mut report = Report::EMPTY;
    let code = if cfg.magic != svc::CONFIG_MAGIC {
        2 // the spawn's patch did not land — nothing is knowable
    } else {
        run(cfg, &mut report)
    };
    report.exit_code = code;
    report.magic = svc::REPORT_MAGIC;
    write_report(&report);
    code
}

/// The probe-and-serve loop. Exit codes: 0 = every client DONE and
/// the drain ran; 3 = idle deadline (loud); 4 = a reply the pipe
/// refused repeatedly (a client died mid-protocol — loud).
fn run(cfg: &Config, rep: &mut Report) -> i32 {
    // The frame-bound probe FIRST (the path's own value error, before
    // any state exists): 1515 bytes can never fit any window.
    let probe = [0u8; 64];
    rep.emsgsize = sys::net_send(probe.as_ptr(), 1515) as i32;
    if rep.emsgsize == -90 {
        rep.flags |= Report::F_EMSGSIZE;
    }

    let seed = if cfg.seed == 0 {
        0x9E37_79B9_7F4A_7C15 // a nonzero stand-in for a buggy patch
    } else {
        cfg.seed
    };
    let ifcfg = IfCfg {
        mac: MacAddr(cfg.mac),
        ip: cfg.ip,
        netmask: cfg.netmask,
        gateway: cfg.gateway,
    };
    // ONE frame of plain locals on the 96-page stack: the stack
    // (~40 KiB), the queue (~6 KiB), the relay, the stages, buffers —
    // the netstack's frame processing nests inside it.
    let stack = NetStack::new(ifcfg, XorShift(seed));
    let mut queue = BrokerQueue::new(NetWire);
    let mut relay = netsock::Relay::new(stack);
    let mut stages = [const { Stage::new() }; MAX_CLIENTS];
    let clients = (cfg.client_count as usize).min(MAX_CLIENTS);
    let mut frame_buf = [0u8; aegis_os::netstack::ETH_FRAME_MAX];
    let mut req_buf = [0u8; netsock::MAX_REQ_LEN];
    let mut payload = [0u8; netsock::MAX_PAYLOAD];
    let mut rep_buf = [0u8; netsock::MAX_REP_LEN];

    let mut idle_since = sys::now_ms();
    let mut drain_until: Option<u64> = None;
    let mut refill_probed = false;
    let mut null_frame = [0u8; 60];
    for (i, b) in null_frame.iter_mut().enumerate() {
        *b = match i {
            0..=5 => 0xFF,            // broadcast destination
            6..=11 => cfg.mac[i - 6], // our source MAC
            12 => 0x5E,               // a probe ethertype nobody answers
            13 => 0xED,
            _ => 0,
        };
    }

    loop {
        let now = sys::now_ms();

        // 1. Ingress: one frame per iteration, non-blocking.
        let n = sys::net_recv(
            frame_buf.as_mut_ptr(),
            aegis_os::netstack::ETH_FRAME_MAX as u64,
        );
        rep.recvs += 1;
        if n > 0 {
            let len = (n as usize).min(aegis_os::netstack::ETH_FRAME_MAX);
            let _ = relay.stack.on_frame(now, &mut queue, &frame_buf[..len]);
            rep.frames_in += 1;
            idle_since = now;
        }

        // 2. Timers: the stack's RTO / delayed-ACK / ARP / TIME_WAIT.
        let _ = relay.stack.poll(now, &mut queue);

        // 3. Pending operations that became ready.
        while let Some((client, reply)) = relay.recheck(now, &mut queue) {
            send_reply(cfg.rep_ch[client], &reply, &mut rep_buf, rep);
        }

        // 4. Requests: drain every client's pipe into its stage.
        for i in 0..clients {
            loop {
                let n = sys::pipe_read(
                    cfg.req_ch[i],
                    req_buf.as_mut_ptr(),
                    netsock::MAX_REQ_LEN as u64,
                );
                if n <= 0 {
                    break; // EAGAIN (empty) or EOF: nothing more now
                }
                idle_since = now;
                if let Err(op) = stages[i].push(now, &req_buf[..n as usize]) {
                    // Oversize or glued: refuse the op's frame, fail closed.
                    let errno = if op == netsock::OP_SEND { 90 } else { 22 };
                    let reply = Rep::result(op, -errno);
                    relay.note_malformed();
                    rep.malformed += 1;
                    send_reply(cfg.rep_ch[i], &reply, &mut rep_buf, rep);
                    break;
                }
                if stages[i].ready() {
                    match stages[i].take(&mut payload) {
                        Ok((req, plen)) => {
                            rep.requests += 1;
                            if let Step::Now(reply) =
                                relay.submit(now, &mut queue, i, &req, &payload[..plen])
                            {
                                if reply.op != OP_DONE && reply.result >= 0 {
                                    rep.replies += 1;
                                }
                                send_reply(cfg.rep_ch[i], &reply, &mut rep_buf, rep);
                            }
                        }
                        Err(reply) => {
                            relay.note_malformed();
                            rep.malformed += 1;
                            send_reply(cfg.rep_ch[i], &reply, &mut rep_buf, rep);
                        }
                    }
                }
            }
        }

        // 5. Bookkeeping + the fairness yield (which also stamps the
        // kernel clock — the bucket's refill windows).
        rep.polls += 1;
        rep.frames_out = (queue.stats.sent + queue.stats.deferred) as u32;
        rep.tcp_sent = relay.stats.stream_sent;
        rep.tcp_recvd = relay.stats.stream_recvd;
        rep.udp_sent = relay.stats.dgram_sent;
        rep.udp_recvd = relay.stats.dgram_recvd;
        rep.timeouts = relay.stats.timeouts;
        rep.cancelled = relay.stats.cancelled;
        rep.live_socks = relay.live_sockets() as u32;
        if rep.tcp_sent > 0 && rep.tcp_recvd >= rep.tcp_sent {
            rep.flags |= Report::F_TCP;
        }
        if rep.udp_sent > 0 && rep.udp_recvd >= rep.udp_sent {
            rep.flags |= Report::F_UDP;
        }
        queue.flush();
        sys::sched_yield();
        let now = sys::now_ms();

        // 6. The exits: drain-after-DONE, or the idle deadline. The
        // relay's `all_finished()` covers its whole four-slot
        // population; THIS service finishes when the clients it was
        // told about (client_count) are done — the unused slots are
        // nobody's business (found live: a one-client lane idled out
        // waiting for three slots that never had a channel).
        let all_done = clients > 0 && (0..clients).all(|i| relay.client_finished(i));
        if all_done {
            if drain_until.is_none() {
                drain_until = Some(now + cfg.drain_ms);
            }
            // The bucket-refill probe, once, after the traffic stops:
            // null frames until the EAGAIN, then a 1.1 s wait (the
            // yield loop keeps the clock stamping), then ONE more —
            // it must succeed (the window refilled).
            if !refill_probed {
                refill_probed = true;
                loop {
                    let r = sys::net_send(null_frame.as_ptr(), 60);
                    if r == 60 {
                        continue;
                    }
                    if r == -11 {
                        rep.throttle_seen = 1;
                    }
                    break;
                }
                let until = sys::now_ms() + 1100;
                while sys::now_ms() < until {
                    let _ = relay.stack.poll(sys::now_ms(), &mut queue);
                    queue.flush();
                    sys::sched_yield();
                }
                if sys::net_send(null_frame.as_ptr(), 60) == 60 {
                    rep.refill_ok = 1;
                    rep.flags |= Report::F_REFILL;
                }
            }
            if now >= drain_until.unwrap_or(0) {
                return 0;
            }
        } else if now.saturating_sub(idle_since) > cfg.idle_ms {
            return 3;
        }
    }
}

/// Encode and deliver one reply; a refused pipe is retried a bounded
/// number of times (the client is parked in recv_wait — a refusal it
/// cannot observe means it died mid-protocol, and the service must
/// not park on a dead client's ring).
fn send_reply(ch: u64, reply: &Rep, buf: &mut [u8; netsock::MAX_REP_LEN], rep: &mut Report) {
    let n = reply.encode(buf);
    if n == 0 {
        rep.malformed += 1;
        return;
    }
    for _ in 0..4 {
        let r = sys::pipe_write(ch, buf.as_ptr(), n as u64);
        if r == n as i64 {
            return;
        }
        if r != -11 {
            rep.malformed += 1; // EACCES/EPIPE: the channel is gone
            return;
        }
        sys::sched_yield(); // EAGAIN: the ring is full — let it drain
    }
    rep.malformed += 1;
}
