//! Ring-3 virtio-blk DRIVER DOMAIN (ADR-0017's first migration): the
//! whole bring-up + one sector read at CPL=3, every register access a
//! `SYS_DEVREG` message to the ring-0 device core — the driver code
//! cannot even NAME a register outside its grant.
//!
//! Invariants (the flat-blob contract): position-dependent code at
//! `mm::user_layout`'s code base, one data page at 0x403000 (the
//! kernel copies the boot info in, then patches `ring_pa` after the
//! spawn); touches nothing but its own pages; ends in SYS_EXIT, never
//! a fault or an unbounded loop.
//!
//! The data page doubles as the RING page (qsize 8: the header,
//! three descriptors, the avail and used rings, the 512-byte buffer
//! and the status byte all fit in one 4 KiB page — the same page the
//! kernel broker-maps for the device, so the domain writes its queue
//! through its user mapping and the device reads it through the
//! IOMMU domain scoped to exactly this driver):
//!
//! ```text
//! 0x403000  u64 ring_pa            (kernel-patched post-spawn)
//! 0x403008  u64 notify_multiplier  (kernel-patched post-spawn)
//! 0x403020  u64 handshake_status   (report: the final STATUS word)
//! 0x403028  u64 used_len           (report: the completion length)
//! 0x403030  u64 device_status      (report: the virtio-blk status byte)
//! 0x403038  u64 data0              (report: the first 8 bytes read)
//! 0x403040  u64 progress           (report: the last completed step — debugging)
//! 0x403100  blk request header     (type u32, reserved u32, sector u64)
//! 0x403120  descriptor table       (3 × 16 B)
//! 0x403160  avail ring             (flags, idx, ring[0])
//! 0x403180  used ring              (flags, idx, entry[0] = id + len)
//! 0x403200  data buffer            (512 B, device-written)
//! 0x403400  status byte            (device-written)
//! ```
#![no_std]

use core::arch::global_asm;

global_asm!(
    r#"
    .section .text.ring3,"ax"
    .globl _ring3_start
_ring3_start:
    /* The SYS_DEVREG message shape: rdi=op (0 read, 1 write),
     * rsi=off, rdx=len, r10=val, r8=region; rax=33. The reply is
     * the value, 0 (a served write), or u64::MAX (refused). The
     * macros clobber rax/rcx/r11 + the argument registers only; rbx,
     * r9, r12..r15 survive every call. */
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

    /* step 1: the boot info */
    mov rbx, [0x403000]             /* ring_pa: the ONE physical
                                       address this driver ever holds —
                                       its own page, kernel-brokered */

    /* step 2: device reset (STATUS is written as the containing
     * dword, exactly like the ring-0 driver's w32 at CC_STATUS) */
    devreg_write 0x14, 4, 0, 0

    /* step 3: read the device's feature words (select, then read);
     * a device without VERSION_1+ACCESS_PLATFORM is refused */
    devreg_write 0x00, 4, 0, 0
    devreg_read  0x04, 4, 0         /* rax = feat_low (wanted mask: 0) */
    devreg_write 0x00, 4, 0, 1
    devreg_read  0x04, 4, 0         /* rax = feat_high */
    and eax, 3                      /* wanted: VERSION_1 | ACCESS_PLATFORM */
    jz fail_nego
    mov r9d, eax                    /* r9 = the negotiated high word */
    mov qword ptr [0x403040], 3              /* progress: features read */

    /* step 4: ACK|DRIVER FIRST (QEMU errors on feature writes before
     * DRIVER), then the negotiated words, then FEATURES_OK — the
     * same order the ring-0 driver uses. */
    devreg_write 0x14, 4, 0, 7
    devreg_write 0x08, 4, 0, 0
    devreg_write 0x0C, 4, 0, 0      /* low: wanted = 0 */
    devreg_write 0x08, 4, 0, 1
    devreg_write 0x0C, 4, 0, r9     /* high: wanted = feat_high & 3 */
    devreg_write 0x14, 4, 0, 15     /* ACK|DRIVER|FEATURES_OK */
    devreg_read  0x14, 4, 0         /* rax = the status word */
    test eax, 8                     /* FEATURES_OK kept? */
    jz fail_nego
    mov qword ptr [0x403040], 4              /* progress: features OK */

    /* step 5: queue 0: select, shrink to 8, learn the notify slot */
    devreg_write 0x16, 2, 0, 0
    devreg_write 0x18, 2, 0, 8
    devreg_read  0x18, 2, 0         /* rax = the granted size */
    cmp eax, 8
    jne fail_nego
    devreg_read  0x1E, 2, 0         /* rax = notify_off */
    mov r12, rax
    imul r12, [0x403008]            /* r12 = notify_off × multiplier */
    mov qword ptr [0x403040], 5              /* progress: queue configured */

    /* step 6: the three ring addresses — the only place the pa is
     * ever written, straight into the queue registers */
    lea rax, [rbx + 0x120]
    devreg_write 0x20, 8, 0, rax    /* QUEUE_DESC */
    lea rax, [rbx + 0x160]
    devreg_write 0x28, 8, 0, rax    /* QUEUE_AVAIL */
    lea rax, [rbx + 0x180]
    devreg_write 0x30, 8, 0, rax    /* QUEUE_USED */
    devreg_write 0x1C, 2, 0, 1      /* QUEUE_ENABLE */

    /* step 7: DRIVER_OK — the device goes live with the domain's
     * own page as its queue */
    devreg_write 0x14, 4, 0, 15
    devreg_read  0x14, 4, 0         /* rax = the live status word */
    mov qword ptr [0x403020], rax            /* report: handshake_status */
    cmp eax, 15
    jne fail_status
    mov qword ptr [0x403040], 6              /* progress: DRIVER_OK */

    /* step 8: build the request in the ring page (user writes —
     * the device reads the same bytes through its IOMMU mapping).
     * desc0: the 16-byte header, chained; desc1: the 512-byte
     * device-writable buffer; desc2: the 1-byte status. */
    mov qword ptr [0x403100], 0              /* type = 0 (BLK_T_IN), reserved 0 */
    mov qword ptr [0x403108], 0              /* sector 0 */
    lea rax, [rbx + 0x100]
    mov qword ptr [0x403120], rax            /* desc0.addr = the header */
    mov dword ptr [0x403128], 16             /* desc0.len */
    mov word ptr [0x40312c], 1              /* desc0.flags = NEXT */
    mov word ptr [0x40312e], 1              /* desc0.next = 1 */
    lea rax, [rbx + 0x200]
    mov qword ptr [0x403130], rax            /* desc1.addr = the buffer */
    mov dword ptr [0x403138], 512            /* desc1.len */
    mov word ptr [0x40313c], 3              /* desc1.flags = WRITE|NEXT — the chain must reach the status descriptor (found live: len 512 came back but no data, no status) */
    mov word ptr [0x40313e], 2              /* desc1.next = 2 */
    lea rax, [rbx + 0x400]
    mov qword ptr [0x403140], rax            /* desc2.addr = the status byte */
    mov dword ptr [0x403148], 1              /* desc2.len */
    mov word ptr [0x40314c], 2              /* desc2.flags = WRITE */
    mov word ptr [0x40314e], 0              /* desc2.next = end of chain */
    mov word ptr [0x403160], 0              /* avail.flags */
    mov word ptr [0x403162], 1              /* avail.idx = 1 */
    mov word ptr [0x403164], 0              /* avail.ring[0] = desc 0 */
    mov word ptr [0x403400], 0x55           /* poison the status byte first */
    mov qword ptr [0x403040], 7              /* progress: request built */

    /* step 9: THE KICK — the queue index (0) at the queue's own
     * notify slot, a 2-byte write (iowrite16, ADR-0016). A refusal
     * here is fatal and loud. */
    devreg_write r12, 2, 1, 0
    cmp rax, -1
    je fail_refused
    mov qword ptr [0x403040], 8              /* progress: kicked */

    /* step 10: the bounded used-ring poll (20M iterations — the
     * same budget the ring-0 driver's poll_used uses). The domain
     * reads its OWN page: no syscall, no kernel involvement. */
    mov r13, 0x1400000
1:  movzx eax, word ptr [0x403182]  /* used.idx */
    test eax, eax
    jnz 2f
    dec r13
    jnz 1b
    jmp fail_timeout
2:  mov qword ptr [0x403040], 9              /* progress: completed */
    /* the completion: used entry[0].len, the device-written status
     * byte, and the data — all read from the domain's own page */
    mov eax, [0x403188]             /* used entry len (u32, zero-extends) */
    mov qword ptr [0x403028], rax            /* report: used_len */
    movzx eax, byte ptr [0x403400]  /* the status byte */
    mov qword ptr [0x403030], rax            /* report: device_status */
    mov rax, [0x403200]             /* the read data (first 8 bytes) */
    mov qword ptr [0x403038], rax            /* report: data0 */

    /* step 11: clean exit — the kernel verifies the report against
     * the ring-0 path's own read of the same sector */
    mov eax, 63                     /* SYS_EXIT */
    xor edi, edi                    /* 0: the happy path */
    syscall

fail_nego:
    mov qword ptr [0x403040], 90
    mov eax, 63
    mov edi, 4
    syscall
fail_status:
    mov qword ptr [0x403040], 91
    mov eax, 63
    mov edi, 5
    syscall
fail_refused:
    mov qword ptr [0x403040], 92
    mov eax, 63
    mov edi, 6
    syscall
fail_timeout:
    mov qword ptr [0x403040], 93
    mov eax, 63
    mov edi, 7
    syscall
"#,
);
