//! Ring-3 e1000 DRIVER DOMAIN (K26, ADR-0017's THIRD migration —
//! virtio-blk was the first, virtio-net the second): the whole NIC
//! bring-up — the quiesce, the MAC + link read, BOTH legacy ring
//! programs (RX at RDBAL, TX at TDBAL), the RX buffer post, the TX
//! descriptor + tail kick — and the DHCP round trip through the
//! domain's OWN descriptor rings, every register access a
//! `SYS_DEVREG` message to the ring-0 device core. The driver code
//! cannot even NAME a register outside its grant; the kernel never
//! touches the device on this path.
//!
//! Invariants (the flat-blob contract): position-dependent code at
//! `mm::user_layout`'s code base, one data page at 0x403000, touches
//! nothing but its own pages, ends in SYS_EXIT, never an unbounded
//! loop.
//!
//! The data page doubles as BOTH descriptor rings + both frame
//! buffers (the vnetdom discipline, e1000 edition: legacy 16-byte
//! descriptors, 16-entry rings, all inside one 4 KiB page — the same
//! page the kernel broker-maps for the device):
//!
//! ```text
//! 0x403000  u64 page_pa            (kernel-patched post-spawn)
//! 0x403020  u64 progress           (report: the last completed step)
//! 0x403028  u64 tx_done            (report: the TX DD bit seen)
//! 0x403030  u64 rx_len             (report: the RX descriptor's length)
//! 0x403038  u64 rx_op              (report: the OFFER's op byte)
//! 0x403040  u64 rx_yiaddr          (report: the OFFER's yiaddr, as read)
//! 0x403048  u64 mac_lo             (report: RAL, via devreg)
//! 0x403050  u64 mac_hi             (report: RAH's low half, via devreg)
//! 0x403058  u64 status_word        (report: STATUS, via devreg)
//! 0x403080  RX ring               (16 × 16 B legacy descriptors)
//! 0x403180  TX ring               (16 × 16 B legacy descriptors)
//! 0x403280  TX frame               (the kernel-seeded 290 B DISCOVER)
//! 0x403400  RX buffer              (up to 1514 B, device-writable)
//! ```
//!
//! The op byte of a received DHCP OFFER sits at eth(14)+ip(20)+udp(8)
//! = frame+42 DECIMAL — 0x403400+42 = 0x40342A; yiaddr at frame+58 =
//! 0x40343A. (K25's lesson is now a written-down constant: the
//! hex/decimal offset confusion that faked a page-rewrite anomaly for
//! five rounds starts HERE, in the blob's literals — every literal
//! below is stated with its derivation.)
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

    /* ── the quiesce: both engines off before the repoint (the
     * ring-0 proof's rings are long torn down, but the discipline
     * is the driver's own: never reprogram a live engine) ── */
    devreg_write 0x100, 4, 0, 0        /* RCTL ← 0 (RX off) */
    devreg_write 0x400, 4, 0, 0        /* TCTL ← 0 (TX off) */

    /* ── the identity: MAC + link THROUGH the devreg channel —
     * ownership means the domain reads the device's OWN registers ── */
    devreg_read 0x5400, 4, 0           /* RAL → MAC bytes 0..4 */
    mov qword ptr [0x403048], rax
    devreg_read 0x5404, 2, 0           /* RAH → MAC bytes 4..6 */
    mov qword ptr [0x403050], rax
    devreg_read 0x8, 4, 0              /* STATUS → the link word */
    mov qword ptr [0x403058], rax
    test eax, 0x2                      /* link up? */
    jz fail_link
    mov qword ptr [0x403020], 2        /* progress: identity read */

    /* ── the RX ring on the domain's OWN page: base, length, one
     * posted buffer (desc 0 → page+0x400), tail=1, then EN|BAM ── */
    lea rax, [r14 + 0x80]
    devreg_write 0x2800, 4, 0, rax     /* RDBAL ← page+0x80 */
    devreg_write 0x2804, 4, 0, 0       /* RDBAH ← 0 (32-bit DMA) */
    devreg_write 0x2808, 4, 0, 256     /* RDLEN ← 16 desc × 16 B */
    devreg_write 0x2810, 4, 0, 0       /* RDH ← 0 */
    lea rax, [r14 + 0x400]
    mov qword ptr [0x403080], rax      /* desc[0].buffer_addr */
    devreg_write 0x2818, 4, 0, 1       /* RDT ← 1 (desc 0 posted) */
    devreg_write 0x100, 4, 0, 0x8002   /* RCTL ← EN|BAM (the OFFER
                                           is broadcast — BAM or it
                                           is dropped silently) */
    mov qword ptr [0x403020], 3        /* progress: RX armed */

    /* ── the TX ring: base, length, heads, then EN ── */
    lea rax, [r14 + 0x180]
    devreg_write 0x3800, 4, 0, rax     /* TDBAL ← page+0x180 */
    devreg_write 0x3804, 4, 0, 0       /* TDBAH ← 0 */
    devreg_write 0x3808, 4, 0, 256     /* TDLEN ← 256 */
    devreg_write 0x3810, 4, 0, 0       /* TDH ← 0 */
    devreg_write 0x3818, 4, 0, 0       /* TDT ← 0 */
    devreg_write 0x400, 4, 0, 2        /* TCTL ← EN */
    mov qword ptr [0x403020], 4        /* progress: TX armed */

    /* ── the DISCOVER's descriptor: the kernel-seeded frame at
     * page+0x280, 290 bytes, EOP|IFCS|RS — then the tail write
     * that FIRES it ── */
    lea rax, [r14 + 0x280]
    mov qword ptr [0x403180], rax      /* desc[0].buffer_addr */
    mov dword ptr [0x403188], 290      /* desc[0].length */
    mov byte ptr [0x40318B], 0x0B      /* desc[0].cmd = EOP|IFCS|RS
                                           (RS: the write-back DD) */
    devreg_write 0x3818, 4, 0, 1       /* TDT ← 1 — the kick */
    mov qword ptr [0x403020], 5        /* progress: DISCOVER fired */

    /* ── the TX completion poll (bounded): the DD write-back bit in
     * desc[0].status, byte 12 of the TX descriptor ── */
    mov rcx, 0x4000000                 /* 64 M spins — the TDH 0→1 +
                                           the write-back are fast */
1:  movzx eax, byte ptr [0x40318C]     /* TX desc[0]+12: DD */
    test al, 1
    jnz 2f
    dec rcx
    jnz 1b
    jmp fail_tx_timeout
2:  mov qword ptr [0x403028], 1        /* report: TX done */
    mov qword ptr [0x403020], 6        /* progress: TX completed */

    /* ── the RX poll (bounded): the OFFER lands in the posted buffer.
     * The budget must outlast QEMU's RCTL flush-queue timer — every
     * RCTL write parks delivery for 1000 ms of the VIRTUAL clock,
     * so the OFFER sits queued a full second before the NIC's first
     * descriptor fetch (measured by the ring-0 proof; same device,
     * same timer, same patience — the poll checks DD every
     * iteration and exits early on success). ── */
    mov rcx, 0xB2D05E00                /* 3 G spins, the ring-0 budget */
3:  movzx eax, byte ptr [0x40308C]     /* RX desc[0]+12: DD */
    test al, 1
    jnz 4f
    dec rcx
    jnz 3b
    jmp fail_rx_timeout
4:  movzx eax, word ptr [0x403088]     /* RX desc[0]+8: the length
                                           (the legacy descriptor is
                                           buffer_addr(8)+length(2),
                                           the TX layout's mirror) */
    mov qword ptr [0x403030], rax
    movzx eax, byte ptr [0x40342A]     /* frame+42 DECIMAL: the op */
    mov qword ptr [0x403038], rax
    mov eax, [0x40343A]                /* frame+58 DECIMAL: yiaddr
                                           (0x400+58 = 0x43A — the
                                           layout test pins this) */
    mov qword ptr [0x403040], rax
    mov qword ptr [0x403020], 7        /* progress: reports read */

    /* clean exit — the kernel verifies every report field */
    mov eax, 63
    xor edi, edi
    syscall

fail_link:
    mov eax, 63
    mov edi, 200
    syscall
fail_tx_timeout:
    mov eax, 63
    mov edi, 201
    syscall
fail_rx_timeout:
    mov eax, 63
    mov edi, 202
    syscall
"#,
);
