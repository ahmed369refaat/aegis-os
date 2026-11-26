//! Ring-3 virtio-net DRIVER DOMAIN (K20/P0-4, ADR-0017's second
//! migration): the whole device bring-up — reset, feature
//! negotiation, BOTH queues (0 = RX, 1 = TX), DRIVER_OK — and a DHCP
//! round trip through the domain's OWN rings, every register access a
//! `SYS_DEVREG` message to the ring-0 device core. The driver code
//! cannot even NAME a register outside its grant; the kernel never
//! touches the device on this path.
//!
//! Invariants (the flat-blob contract): position-dependent code at
//! `mm::user_layout`'s code base, one data page at 0x403000, touches
//! nothing but its own pages, ends in SYS_EXIT, never an unbounded
//! loop.
//!
//! The data page doubles as BOTH ring sets + both frame buffers
//! (qsize 8 keeps each queue's descriptor table, avail and used
//! rings, and the DHCP-sized buffers inside one 4 KiB page — the
//! same page the kernel broker-maps for the device):
//!
//! ```text
//! 0x403000  u64 page_pa            (kernel-patched post-spawn)
//! 0x403008  u64 notify_multiplier  (kernel-patched post-spawn)
//! 0x403020  u64 handshake_status   (report: the final STATUS word)
//! 0x403028  u64 tx_used_len        (report: the TX completion length)
//! 0x403030  u64 rx_used_len        (report: the RX completion length)
//! 0x403038  u64 rx_op              (report: the OFFER's op byte)
//! 0x403040  u64 rx_yiaddr          (report: the OFFER's yiaddr, big-endian)
//! 0x403048  u64 mac_lo             (report: MAC bytes 0..4, via devreg)
//! 0x403050  u64 mac_hi             (report: MAC bytes 4..6, via devreg)
//! 0x403058  u64 progress           (report: the last completed step)
//! 0x403060  RX desc 0              (16 B)
//! 0x403070  TX desc 0              (16 B)
//! 0x403080  RX avail ring          (flags, idx, ring[0], pad)
//! 0x4030A0  RX used ring           (flags, idx, entry[0])
//! 0x4030F0  TX avail ring
//! 0x403110  TX used ring
//! 0x403200  TX frame               (12 B vnet hdr + the kernel-seeded
//!                                   290 B DHCP DISCOVER)
//! 0x403400  RX buffer              (12 B vnet hdr + up to 1514 B —
//!                                   the posted device-writable buffer)
//! ```
//!
//! The op byte of a received DHCP OFFER sits at eth(14)+ip(20)+udp(8)
//! = frame+42; yiaddr at frame+58 (dhcp+16).
#![no_std]

use core::arch::global_asm;

global_asm!(
    r#"
    .section .text.ring3,"ax"
    .globl _ring3_start
_ring3_start:
    /* The SYS_DEVREG message shape: rdi=op (0 read, 1 write),
     * rsi=off, rdx=len, r10=val, r8=region; rax=33. The reply is
     * the value, 0 (a served write), or u64::MAX (refused). */
.macro devreg_read off, len, region
    xor edi, edi
    mov rsi, \off
    mov edx, \len
    mov r8d, \region
    mov eax, 33
    syscall
.endm
.macro devreg_write off, len, region, val
    mov edi, 1
    mov rsi, \off
    mov edx, \len
    mov r10, \val
    mov r8d, \region
    mov eax, 33
    syscall
.endm
    /* r14 = the page's own PA (the ONE physical address this driver
     * ever holds — its own page, kernel-brokered). */
    mov r14, [0x403000]

    /* ── the modern handshake, the same discipline as the ring-0
     * driver and the virtio-blk domain ── */
    devreg_write 0x14, 4, 0, 0        /* reset */
    devreg_write 0x00, 4, 0, 1        /* feature select: high */
    devreg_read  0x04, 4, 0           /* rax = feat_high */
    and eax, 3                         /* want VERSION_1|ACCESS_PLATFORM */
    jz fail_nego
    mov r9d, eax                       /* r9 = negotiated high */
    devreg_write 0x14, 4, 0, 7        /* ACK|DRIVER first */
    devreg_write 0x08, 4, 0, 0        /* driver feature select: low */
    devreg_write 0x0C, 4, 0, 0        /* low: wanted = 0 */
    devreg_write 0x08, 4, 0, 1        /* select high */
    devreg_write 0x0C, 4, 0, r9       /* high: VERSION_1|ACCESS_PLATFORM */
    devreg_write 0x14, 4, 0, 15       /* ACK|DRIVER|FEATURES_OK */
    devreg_read  0x14, 4, 0
    test eax, 8                        /* FEATURES_OK kept? */
    jz fail_nego
    mov qword ptr [0x403058], 4       /* progress: features OK */

    /* ── the MAC: read through the device-config region (region 3) —
     * ownership means the domain reads the device's OWN config. */
    devreg_read 0, 4, 3               /* rax = MAC bytes 0..4 */
    mov qword ptr [0x403048], rax
    devreg_read 4, 2, 3               /* rax = MAC bytes 4..6 */
    mov qword ptr [0x403050], rax
    mov qword ptr [0x403058], 5       /* progress: MAC read */

    /* ── queue 0 (RX): select, shrink to 8, addresses, enable ── */
    devreg_write 0x16, 2, 0, 0
    devreg_write 0x18, 2, 0, 8
    devreg_read  0x18, 2, 0
    cmp eax, 8
    jne fail_nego
    devreg_read  0x1E, 2, 0           /* rax = RX notify_off */
    imul rax, [0x403008]
    mov r12, rax                       /* r12 = the RX notify slot */
    lea rax, [r14 + 0x60]
    devreg_write 0x20, 8, 0, rax      /* QUEUE_DESC */
    lea rax, [r14 + 0x80]
    devreg_write 0x28, 8, 0, rax      /* QUEUE_AVAIL */
    lea rax, [r14 + 0xA0]
    devreg_write 0x30, 8, 0, rax      /* QUEUE_USED */
    devreg_write 0x1C, 2, 0, 1       /* QUEUE_ENABLE */
    mov qword ptr [0x403058], 6       /* progress: RX queue */

    /* ── queue 1 (TX): the same dance ── */
    devreg_write 0x16, 2, 0, 1
    devreg_write 0x18, 2, 0, 8
    devreg_read  0x18, 2, 0
    cmp eax, 8
    jne fail_nego
    devreg_read  0x1E, 2, 0           /* rax = TX notify_off */
    imul rax, [0x403008]
    mov r13, rax                       /* r13 = the TX notify slot */
    lea rax, [r14 + 0x70]
    devreg_write 0x20, 8, 0, rax
    lea rax, [r14 + 0xF0]
    devreg_write 0x28, 8, 0, rax
    lea rax, [r14 + 0x110]
    devreg_write 0x30, 8, 0, rax
    devreg_write 0x1C, 2, 0, 1
    mov qword ptr [0x403058], 7       /* progress: TX queue */

    /* ── post the RX buffer (desc 0: 12 vnet hdr + 1514 max, WRITE),
     * publish to the RX avail ring, then DRIVER_OK ── */
    lea rax, [r14 + 0x400]
    mov qword ptr [0x403060], rax     /* desc0.addr */
    mov dword ptr [0x403068], 1526    /* desc0.len = 12+1514 */
    mov word ptr [0x40306c], 2        /* desc0.flags = WRITE */
    mov word ptr [0x40306e], 0        /* desc0.next = end */
    mov word ptr [0x403080], 0        /* avail0.flags */
    mov word ptr [0x403082], 1        /* avail0.idx */
    mov word ptr [0x403084], 0        /* avail0.ring[0] = desc 0 */
    devreg_write 0x14, 4, 0, 15       /* DRIVER_OK — the device is live
                                         on THIS domain's rings */
    devreg_read  0x14, 4, 0
    mov qword ptr [0x403020], rax     /* report: handshake_status */
    cmp eax, 15
    jne fail_status
    devreg_write r12, 2, 1, 0         /* kick queue 0 (the RX post) */
    cmp rax, -1
    je fail_refused
    mov qword ptr [0x403058], 8       /* progress: DRIVER_OK + RX posted */

    /* ── the TX: desc 0 = 12 hdr + 290 DISCOVER (kernel-seeded),
     * publish, kick queue 1 at ITS slot ── */
    lea rax, [r14 + 0x200]
    mov qword ptr [0x403070], rax     /* desc0.addr */
    mov dword ptr [0x403078], 302     /* desc0.len = 12+290 */
    mov word ptr [0x40307c], 0        /* flags = 0 */
    mov word ptr [0x40307e], 0        /* next = end */
    mov word ptr [0x4030F0], 0        /* avail1.flags */
    mov word ptr [0x4030F2], 1        /* avail1.idx */
    mov word ptr [0x4030F4], 0        /* avail1.ring[0] */
    devreg_write r13, 2, 1, 1         /* THE KICK: queue index 1 */
    cmp rax, -1
    je fail_refused
    mov qword ptr [0x403058], 9       /* progress: DISCOVER kicked */

    /* ── the TX completion poll (bounded) ── */
    mov rcx, 0x1400000
1:  movzx eax, word ptr [0x403112]   /* TX used.idx */
    test eax, eax
    jnz 2f
    dec rcx
    jnz 1b
    jmp fail_tx_timeout
2:  mov eax, [0x403118]              /* TX used entry[0].len */
    mov qword ptr [0x403028], rax
    mov qword ptr [0x403058], 10      /* progress: TX completed */

    /* ── the RX poll (bounded): slirp's OFFER lands in the posted
     * buffer ── */
    mov rcx, 0x1400000
3:  movzx eax, word ptr [0x4030A2]   /* RX used.idx */
    test eax, eax
    jnz 4f
    dec rcx
    jnz 3b
    jmp fail_rx_timeout
4:  mov eax, [0x4030A8]              /* RX used entry[0].len */
    mov qword ptr [0x403030], rax
    /* the OFFER's payload: op at frame+42, yiaddr at frame+58 */
    movzx eax, byte ptr [0x403400 + 12 + 42]
    mov qword ptr [0x403038], rax
    mov eax, [0x403400 + 12 + 58]
    mov qword ptr [0x403040], rax
    mov qword ptr [0x403058], 11      /* progress: OFFER received */

    /* clean exit — the kernel verifies every report field */
    mov eax, 63
    xor edi, edi
    syscall

fail_nego:
    mov qword ptr [0x403058], 90
    mov eax, 63
    mov edi, 4
    syscall
fail_status:
    mov qword ptr [0x403058], 91
    mov eax, 63
    mov edi, 5
    syscall
fail_refused:
    mov qword ptr [0x403058], 92
    mov eax, 63
    mov edi, 6
    syscall
fail_tx_timeout:
    mov qword ptr [0x403058], 93
    mov eax, 63
    mov edi, 7
    syscall
fail_rx_timeout:
    mov qword ptr [0x403058], 94
    mov eax, 63
    mov edi, 8
    syscall
"#,
);
