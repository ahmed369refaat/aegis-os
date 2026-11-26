//! Ring-3 netd (K20/P0-2): the brokered socket's DATA PATH proven at
//! CPL=3 — one DHCP DISCOVER out through `SYS_NET_SEND`, the OFFER
//! back through `SYS_NET_RECV`, then the throttle and frame-bound
//! edges, all against the kernel's policy gate (Device capability +
//! the token bucket) and the live virtio-net rings.
//!
//! Invariants (the flat-blob contract): position-dependent code at
//! `mm::user_layout`'s code base, one data page at 0x403000, touches
//! nothing but its own pages, ends in SYS_EXIT. The kernel seeds the
//! two frames it sends (the DISCOVER reuses `netutil`'s builder —
//! P0-2 proves the PATH, not DHCP crafting in asm); the blob verifies
//! what came BACK and reports the numbers for the kernel-side check.
//!
//! Data page:
//! ```text
//! 0x403000  the DHCP DISCOVER frame (290 B, kernel-seeded)
//! 0x403200  the 60-byte null frame    (kernel-seeded; slirp drops it)
//! 0x403800  the receive buffer        (NET_RECV target, blob-owned)
//! 0x403C00  the report block          (blob-written, kernel-verified)
//!   +00  first_send_ret (expect 290 — send(2) answers bytes)
//!   +08  recv_len       (the OFFER's copied length)
//!   +10  yiaddr         (the offered address, must be nonzero)
//!   +18  dhcp_op        (expect 2 = BOOTREPLY)
//!   +20  null_sends     (the 60-byte sends that fit the bucket: 20)
//! ```
//!
//! Exit codes: 0 = the run completed and the report block holds the
//! raw syscall returns (the kernel-side verification in
//! `drvstack/vnet.rs` owns every interpretation — a blob that only
//! records cannot mis-check anything).
#![no_std]

use core::arch::global_asm;

global_asm!(
    r#"
    .section .text.ring3,"ax"
    .globl _ring3_start
_ring3_start:
    /* 1. NET_SEND(DISCOVER, 290): Linux-style, RAX answers the byte
     * count. The policy gate ran first in the kernel (Device cap
     * WRITE, the domain's socket, the bucket) — a refusal lands here
     * as -errno. The blob RECORDS the raw returns; the kernel-side
     * verification owns every interpretation (P0-2 proves the path,
     * and a blob that only records cannot mis-check anything). */
    mov eax, 9
    mov edi, 0x403000
    mov esi, 290
    syscall
    mov qword ptr [0x403C00], rax     /* send #1's raw return */

    /* 2. NET_RECV(0x403800, 1514): up to four attempts — nothing
     * ready yet is -EAGAIN (the offer chases the TX completion), so
     * yield once between attempts. The raw return is recorded; the
     * frame lands at 0x403800 for the kernel to verify. */
    mov r13d, 4
1:  mov eax, 10
    mov edi, 0x403800
    mov esi, 1514
    syscall
    cmp rax, 0
    jg 2f
    mov eax, 24
    syscall
    dec r13d
    jnz 1b
2:  mov qword ptr [0x403C08], rax     /* the recv's raw return */
    movzx eax, byte ptr [0x403842]
    mov qword ptr [0x403C30], rax     /* the op byte AS THE BLOB SEES IT right after the recv */

    /* 3. the throttle exhaustion: 60-byte null frames until the
     * bucket refuses. burst=1514, the DISCOVER took 290 -> 1224
     * tokens: exactly 20 fit, the 21st must refuse EAGAIN. */
    xor r12d, r12d
3:  mov eax, 9
    mov edi, 0x403200
    mov esi, 60
    syscall
    cmp rax, 60
    jne 4f
    inc r12d
    jmp 3b
4:  mov qword ptr [0x403C18], rax     /* the throttle refusal's raw return */
    mov qword ptr [0x403C20], r12     /* the 60-byte sends that fit */

    /* 4. the frame-bound probe: 1515 bytes can never fit any window —
     * -EMSGSIZE (90), the value error, not a throttle. */
    mov eax, 9
    xor edi, edi
    mov esi, 1515
    syscall
    mov qword ptr [0x403C28], rax     /* the probe's raw return */
    movzx eax, byte ptr [0x403842]
    mov qword ptr [0x403C38], rax     /* the op byte after the throttle loop + probe */

    /* 5. exit 0 — the report IS the raw truth; the kernel verifies. */
    mov eax, 63
    xor edi, edi
    syscall

    /* the failure exits (self-documented, the preempt-blob family). */
200: mov eax, 63
    mov edi, 200
    syscall
201: mov eax, 63
    mov edi, 201
    syscall
202: mov eax, 63
    mov edi, 202
    syscall
203: mov eax, 63
    mov edi, 203
    syscall
204: mov eax, 63
    mov edi, 204
    syscall
205: mov eax, 63
    mov edi, 205
    syscall
"#
);
