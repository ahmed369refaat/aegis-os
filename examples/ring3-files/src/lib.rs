//! Ring-3 files blob (Round J example): the full Unix file lifecycle
//! from CPL=3 — pipe(), write into it, read back and VERIFY, dup
//! keeping a pipe end alive past its original's close, open(O_CREAT)/
//! write/read-back through a dup'd independent cursor, and the three
//! negative probes (EBADF / ENOENT / EBADF-on-closed).
//!
//! Every step checks the kernel's answer and exits 99 (loud) on the
//! first wrong one; only a fully verified lifecycle exits 42. The
//! console markers ("J:pipe ok" etc.) ride fd 1 — the runtime's
//! device alias — so the CI greps prove each phase ran.
//!
//! Data-page layout (kmain builds the matching array — the addresses
//! here ARE the contract):
//!
//! ```text
//! 0x403000  MSG1   "pipe bytes from cpl3\n"      (21)  pipe round-trip
//! 0x403040  MSG2   "dup keeps ends alive\n"      (21)  dup survival
//! 0x403080  FMSG   "aegis file roundtrip\n"      (21)  file content
//! 0x4030C0  PATH   "/pub/round-j.txt\0"          (17)  create target
//! 0x403100  NXPATH "/no/such/file\0"             (14)  ENOENT probe
//! 0x403140  M1     "J:pipe ok\n"                 (10)  markers
//! 0x403160  M2     "J:dup ok\n"                   (9)
//! 0x403180  M3     "J:file ok\n"                 (10)
//! 0x4031A0  M4     "J:neg ok\n"                   (9)
//! 0x403800  RBUF1  read destinations (64 bytes, zeroed by kmain)
//! 0x403900  RBUF2
//! 0x403A00  RBUF3
//! ```
//!
//! ABI (docs/ABI-VERSION.md, internal v0.3): nr in RAX; args in RDI,
//! RSI, RDX, R10, ... (dup2's newfd is the SECOND argument — RSI);
//! RAX = result or -errno. PIPE packs `(write_fd << 8) | read_fd`.
#![no_std]

use core::arch::global_asm;

global_asm!(
    r#"
    .section .text.ring3,"ax"
    .globl _ring3_start
_ring3_start:
    /* ── Phase P: pipe() -> (r=3, w=4); write MSG1 in; read back; verify ── */
    mov eax, 12                /* SYS_PIPE */
    syscall
    cmp rax, 0x0403            /* (w=4 << 8) | r=3 — stdio keeps 0..2 */
    jne 9f
    mov eax, 1                 /* SYS_WRITE */
    mov edi, 4                 /* the pipe's write end */
    mov esi, 0x00403000        /* MSG1 */
    mov edx, 21
    syscall
    cmp rax, 21
    jne 9f
    mov eax, 0                 /* SYS_READ */
    mov edi, 3                 /* the read end */
    mov esi, 0x00403800        /* RBUF1 */
    mov edx, 64
    syscall
    cmp rax, 21
    jne 9f
    mov rsi, 0x00403000        /* MSG1 */
    mov rdi, 0x00403800        /* RBUF1 */
    mov rcx, 21
    call cmp_bytes
    test eax, eax
    jnz 9f
    mov eax, 1                 /* console marker via fd 1 */
    mov edi, 1
    mov esi, 0x00403140        /* M1 "J:pipe ok" */
    mov edx, 10
    syscall
    cmp rax, 10
    jne 9f

    /* ── Phase D: dup(3->7); close(3); the dup'd end must still read ── */
    mov eax, 13                /* SYS_DUP */
    mov edi, 3
    mov esi, 7                 /* arg2 (dup2's newfd) rides RSI */
    syscall
    cmp rax, 7
    jne 9f
    mov eax, 3                 /* SYS_CLOSE */
    mov edi, 3
    syscall
    test rax, rax
    jnz 9f
    mov eax, 1                 /* write MSG2 through w=4 */
    mov edi, 4
    mov esi, 0x00403040
    mov edx, 21
    syscall
    cmp rax, 21
    jne 9f
    mov eax, 0                 /* read through the SURVIVING dup fd 7 */
    mov edi, 7
    mov esi, 0x00403900        /* RBUF2 */
    mov edx, 64
    syscall
    cmp rax, 21
    jne 9f
    mov rsi, 0x00403040
    mov rdi, 0x00403900
    mov rcx, 21
    call cmp_bytes
    test eax, eax
    jnz 9f
    mov eax, 1
    mov edi, 1
    mov esi, 0x00403160        /* M2 "J:dup ok" */
    mov edx, 9
    syscall
    cmp rax, 9
    jne 9f

    /* ── Phase F: open(O_CREAT|O_RDWR) -> 5; dup(5->6) BEFORE the write
       (the duplicate's cursor is a snapshot at 0); write via 5; read
       back via 6 from the snapshot cursor; close(5); the dup reads EOF
       at pos 19 and survives the original's close. ── */
    mov eax, 2                 /* SYS_OPEN */
    mov edi, 0x004030C0        /* "/pub/round-j.txt" */
    mov esi, 6                 /* O_READ|O_WRITE|O_CREAT */
    mov edx, 0x1A4             /* mode 0o644 */
    syscall
    cmp rax, 3                 /* fd 3 was freed by phase D's close(3):
                                  lowest-free recycles it — Unix rule,
                                  proven live right here */
    jne 9f
    mov eax, 13                /* SYS_DUP: 3 -> 6 */
    mov edi, 3
    mov esi, 6
    syscall
    cmp rax, 6
    jne 9f
    mov eax, 1                 /* write FMSG via the original fd 3 */
    mov edi, 3
    mov esi, 0x00403080
    mov edx, 21
    syscall
    cmp rax, 21
    jne 9f
    mov eax, 0                 /* read back via the dup's cursor 0 */
    mov edi, 6
    mov esi, 0x00403A00        /* RBUF3 */
    mov edx, 64
    syscall
    cmp rax, 21
    jne 9f
    mov rsi, 0x00403080
    mov rdi, 0x00403A00
    mov rcx, 21
    call cmp_bytes
    test eax, eax
    jnz 9f
    mov eax, 3                 /* close the ORIGINAL file fd */
    mov edi, 3
    syscall
    test rax, rax
    jnz 9f
    mov eax, 0                 /* the dup survives: pos 19 -> EOF -> 0 */
    mov edi, 6
    mov esi, 0x00403A40
    mov edx, 8
    syscall
    test rax, rax
    jnz 9f
    mov eax, 1
    mov edi, 1
    mov esi, 0x00403180        /* M3 "J:file ok" */
    mov edx, 10
    syscall
    cmp rax, 10
    jne 9f

    /* ── Phase N: the refusals keep their errno identities ── */
    mov eax, 0                 /* read on a never-open fd */
    mov edi, 99
    mov esi, 0x00403800
    mov edx, 4
    syscall
    cmp rax, -9                /* -EBADF */
    jne 9f
    mov eax, 2                 /* open a path that does not exist */
    mov edi, 0x00403100        /* "/no/such/file" */
    mov esi, 1                 /* O_READ */
    xor edx, edx
    syscall
    cmp rax, -2                /* -ENOENT */
    jne 9f
    mov eax, 1                 /* write through the CLOSED pipe fd 3 */
    mov edi, 3
    mov esi, 0x00403000
    mov edx, 4
    syscall
    cmp rax, -9                /* -EBADF */
    jne 9f
    mov eax, 1
    mov edi, 1
    mov esi, 0x004031A0        /* M4 "J:neg ok" */
    mov edx, 9
    syscall
    cmp rax, 9
    jne 9f

    mov eax, 63                /* SYS_EXIT */
    mov edi, 42                /* every step of the lifecycle verified */
    syscall
9:  mov eax, 63                /* SYS_EXIT */
    mov edi, 99                /* WRONG answer — loud */
    syscall

    /* rsi = A, rdi = B, rcx = len -> eax = 0 when equal, 1 when not */
cmp_bytes:
    xor eax, eax
1:  test rcx, rcx
    jz 2f
    mov al, [rsi]
    cmp al, [rdi]
    jne 3f
    inc rsi
    inc rdi
    dec rcx
    jmp 1b
2:  xor eax, eax
    ret
3:  mov eax, 1
    ret
"#,
);
