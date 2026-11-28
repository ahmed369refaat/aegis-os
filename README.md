# AegisOS

**A secure OS core that actually boots: a `no_std`, zero-dependency policy kernel with Unix-philosophy semantics (VFS with Unix permissions and chroot, pipes, signals, fd tables, CFS scheduling, buddy allocator, brokered sockets) under strict per-domain isolation, a graduated behavior-driven security monitor — and a bootable x86_64 kernel that runs it all on real hardware memory.**

[![CI](https://github.com/ahmed369refaat/aegis-os/actions/workflows/ci.yml/badge.svg)](https://github.com/ahmed369refaat/aegis-os/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests: 983](https://img.shields.io/badge/tests-983%20passing-brightgreen.svg)](tests/)
[![Boot](https://img.shields.io/badge/boots%20in%20QEMU-ring--3%20isolation%20live%20%F0%9F%9F%A2-brightgreen.svg)](#quick-start)

> The name: **Aegis** (the shield). One rule shapes the whole design: everything runs inside an isolated `Domain`, and every privilege is granted once and can only ever shrink.

## Current status — honestly stated

- **(P1-2) real binaries through the signed package path + the documented toolchain:**
  the repo fixture's packages now carry REAL programs — `r1/hello` 1.1.0's payload is the
  stripped gcc userland ELF (the same bytes the ext2 disk serves as `/bin/hello`), and a
  third package `r1/netcat` delivers the P1-1 socket client itself. The in-VM lane runs
  FOUR rounds (install → upgrade-to-a-real-ELF → remove → install-the-netcat) with each
  round's installed tree verified byte-exact AND parsed by the exec loader's own plan
  gate — a package that delivered bytes that are not a genuine image cannot pass. The
  netcat image fits the repo's bounds because its pinned blocks and bss ride the data
  segment's NOLOAD memsz tail (13,192 → 8,576 B). `BUILD.md` is now the toolchain map:
  the three citizen types (gcc freestanding / rustc ELF + custom ld / Rust lib+bin
  composition), the memory contracts, the check scripts, and the package path. Found
  live on the way: a 9 KiB kmain verification buffer blew the 16 KiB kernel stack and
  the corruption surfaced far away as a dead CoW entry in the fork lane — the verifier
  now streams 4-KiB chunks; and the first VFS sizing crossed `Kernel<4096>`'s 512-KiB
  boot-stack budget, which the capacity test caught loudly (the spills are now 5×10 KiB,
  measured for the netcat transaction's commit peak).
- **(P1-1) the TCP/IP stack LIVE at ring 3 — the userspace sockets surface:** the policy
  core's own netstack (`src/netstack/`) runs as a REAL CPL=3 ELF service domain
  (`tcpip/`, the NETSVC memory contract, spawned by the kernel's new `spawn_user_elf` —
  the spawn twin of the execve loader), with its clients over capability-mediated byte
  channels. Egress has exactly one exit (`SYS_NET_SEND` through the broker's token
  bucket and broker-mapped rings), ingress exactly one entrance (`SYS_NET_RECV`); the
  service NEVER parks (a poll loop cannot deadlock). The q35 lane proves it live, with
  a **gcc freestanding static client** (`userland-netcat`): `[NET] stack=live tcp=1
  udp=1 broker=1` and `[NET] client_roundtrip=ok` — socket → connect → send → the
  host echo servers → recv → close, TCP and UDP, the bucket's EAGAIN observed and
  REFILLED (the kernel clock's stamp at `sched_yield` works), and the client's own
  probes answered `-EPERM` (denied by policy — a client cannot bypass the broker).
  Ten live-found bugs on the way, all fixed and documented in the commit: LTO
  const-folding the patched config page, the SSE `#UD` (ring 3 has no FPU state),
  non-page-aligned `translate()` offsets, the drain scrubbing report pages before the
  reads, the dgram `connect` auto-bind gap in the core, and the **syscall-entry tick
  seam** — SYSCALL enters CPL0 with IF=1 on this QEMU, a preempt tick between `swapgs`
  and `cli` is a CPL0 timer frame, and this step is the first syscall-heavy long run
  under the live timer (the step now pauses ticks around its run; the P2 answer is a
  stub-level stack switch for CPL0-origin interrupt frames).
- **K20 (the P0 hardening round, three items lane-proven):**
  **(P0-1) production limits, measured** — the fixed tables now speak their real workloads: `MAX_SYSCALL_MSG` 32→2 KiB, `MAX_WAKE_FRAMES` 8→256, `MAX_CHILDREN` 4→32, IPC channels 16→64, pipe buffer 2→16 KiB, domain stack 1→2 MiB — every raise carries a measured cost and a host accounting test, plus a `[CAP]` boot selftest that EXERCISES the new ceilings on every lane (fills them, verifies, frees, count=0). What was NOT raised and why is in `docs/capacity.md` (inline inode payloads, ABI width, VT-d contexts, the frame pool).
  **(P0-2) the network data path** — `SYS_NET_SEND(9)`/`SYS_NET_RECV(10)` are live at the ring-3 entry, ordered fail-closed (frame bound EMSGSIZE → live-session ENODEV → range EFAULT → the core policy gate EACCES/EAGAIN → copy → the wire), driving the CPL0 proof's broker-mapped virtio-net rings through a live-session static. A ring-3 netd domain proves the round trip on the q35 lanes: a 290-byte DHCP DISCOVER out at CPL=3, slirp's 590-byte OFFER back (`op=BOOTREPLY`, yiaddr 10.0.2.15), the bucket exhausting after 1+20 sends (EAGAIN, no clock advance), a 1515-byte send refusing -EMSGSIZE. The core's burst grew 64→1514 bytes — the old default could never pass the boot's own 290-byte frame; a frame that can never fit any window is now `TooLong`→EMSGSIZE, never a throttle.
  **(P0-3) the gcc userland citizen** — the kernel binary is no longer the only root: `gcc -ffreestanding -nostdlib` builds `/bin/hello` (a real compiler's ELF, linked at the exec cage's vaddrs), `mkext2.py` carries it on the ext2 disk, the boot reads its 9 direct blocks off AHCI into the exec registry's new disk slot, and a ring-3 caller `execve`s it — the image runs through the same loader/cage/quota/policy gates and answers `exit_group(42)` (the caller's refusal codes are 100+|errno|, so only the image's own exit answers 42). Its arrival fixed a real core bug: `Inode::parse`'s leftover `off < 44` guard refused every inode that starts a sector — one in four — now removed with a regression test.
  **(P0-4) the second ring-3 driver domain** — virtio-net, migrated the way virtio-blk was (ADR-0017): a CPL=3 domain (driver profile: DEVREG+EXIT only) brings the NIC up from RESET through the SYS_DEVREG channel — features, the MAC read through the device-config window, BOTH queues in its own one-page ring layout, DRIVER_OK, the RX post, the TX publish + kick at the queue's own notify slot, both completion polls — 32 devreg ops served, 0 refused, and a DHCP round trip on the domain's OWN rings (DISCOVER out, OFFER back, the domain's devreg MAC read matching the kernel's own). A rogue domain hammering out-of-window offsets loses its device (5 refusals counted, the ladder closed the channel).
- **(K28) the connection flags + the hostile battery + the zero-vulnerability live proof** (`tls/src/tests/hostile.rs` + the lane's impostor servers): `TlsOptions` — SNI (sent, and `PinnedRequireName` checks the certificate's CN against it), ALPN (offered, the server's answer must be one we offered), the verify mode (`Pinned` / `PinnedRequireName` / TOFU — the signature always verifies), and the hostile-record budget; a 13-test violent battery over the recorded flight — the every-byte mutation sweep (~3.8k cases: no security-relevant byte verifies or releases plaintext), every truncation, header lies, 500-record storms then the real flight, the downgrade surgery, the named trust refusals, the replay (refused by the AEAD's own nonce sequence), the every-byte AEAD tamper, X25519 degenerate peers; two REAL holes found and closed (the unvalidated ChangeCipherSpec skip — now the RFC D.4 shape or `BadHandshake`; `build_client_hello` not moving the phase — a rebuild double-hashed the transcript); and the live proof: two impostor servers on every boot (a different key → the pin refuses; the same key under the wrong name → the name refuses), 2 of 2 refused by name, teardown clean.
- **(K27) TLS 1.3 LIVE over the kernel's own TCP/IP stack — the transport-security layer** (`tls/` + `drvstack/tls.rs`): a complete TLS 1.3 client (X25519, ChaCha20-Poly1305, HKDF-SHA-256, the full key schedule, the record layer, the handshake machine with the pinned Ed25519 CertificateVerify and both Finished MACs) — no_std, no-alloc, zero external crates, zero unsafe — pinned by every RFC vector, a 300-case randomized AEAD sweep, an OpenSSL keylog comparison, and a recorded real-server flight replayed offline; live on the q35 lane: the kernel's own TCP/IP stack over the e1000 through slirp to a real OpenSSL server on the host — the full handshake, one encrypted GET, the PONG echo decrypted in the kernel. The lane also exposed and fixed K24's connect bug (the TCB orphaned on `ArpPending`: the SYN left but the fd never learned its TCB — `NotBound` forever).
  **(K26) the e1000, the third ring-3 driver domain — real-NIC-class hardware driven from CPL=3** (`drvstack/e1kdom.rs` + `examples/ring3-e1kdom`): the kernel keeps only the minimal ring-0 half (the claim, ONE registered device-core window covering the whole BAR0, the broker mapping of the domain's own page into the NIC's IOMMU domain, the DHCP seed, the run, the teardown); everything that used to be driver logic — the quiesce, the MAC/link read, BOTH legacy descriptor ring programs (RDBAL/RDBAH/RDLEN/RDT/RCTL, TDBAL/TDLEN/TCTL), the RX buffer post, the TX descriptor build + tail kick, both completion polls — runs at CPL=3 in a flat blob whose EVERY register access is a `SYS_DEVREG` message window-checked at serve time. The proof (the vnetdom discipline, legacy-descriptor edition, live on the q35 lane): 18 devreg ops served / 0 refused, a full DHCP exchange through the domain's OWN rings (290-byte DISCOVER out, 594-byte OFFER back, op/yiaddr verified), the MAC read through the devreg channel matching the kernel's own RAL/RAH read — two independent paths through the same device — plus the rogue containment (5 out-of-window messages refused, the refusal ladder closing the channel). A host test pins the data-page layout (offsets derived, not guessed — it caught a real 2-byte offset bug on landing). With it, the migration pattern is three-for-three (virtio-blk, virtio-net, e1000) and the ENODEV-era "virtual-only" NIC story is closed: the e1000's CPL0 proof AND its ring-3 driver domain both run the full IOMMU-enforced round trip on every q35 boot.

  **(P0-5, K21) the package manager + the last of its file-family arms** — `pkg/` is the AegisOS package manager as a first-class workspace crate: `no_std`, **no allocator, zero external crates** (the supply chain it defends is not extended by its own build — every primitive is inline: SHA-256/512 pinned by FIPS vectors, Ed25519 pinned by RFC 8032 §7.1 vector 1 plus randomized consistency suites, CRC-32, constant-time comparison). File-only packages by design (no script field; hook paths refused); Ed25519-verified canonical manifests before any staging; per-file re-hash through a fresh open (TOCTOU); staged extraction with a streaming windowed LZ4 ring decoder and declared-size + ratio-cap bomb guards; a WAL journaled, rename-committed, crash-recoverable transaction layer (O_EXCL lock, disk-full rollback, mid-rename crash reversal — all test-proven); a backtracking solver with cycle diagnostics and adversarial-graph budgets; the root→repo→index→package trust chain with admin-pinned TOFU fallback and per-repo monotonic epoch replay defense. 48 host tests cover the threat model (`pkg/THREAT_MODEL.md`; `pkg/BUILD.md` documents the domain's least-privilege mask). The kernel side landed with it: **`stat(2)` (`SYS_STAT` 34, Linux newfstatat 262) and `rename(2)` (`SYS_RENAME` 35, Linux rename 82/renameat 264)** — the metadata read gated by an FsNode READ capability (the 24-byte struct contract), the atomic re-parent with POSIX file-destination replacement, inode identity preservation, EISDIR refusals for directory destinations and subtree cycles, and WRITE caps on both parents (unlink ∪ create rules) — extending the service profile, core-tested (`stat_fills_the_24_byte_contract_and_gates`, `rename_reparents_replaces_and_refuses`) and lane-proven by the full `--verify` boot.
  **The former open anomaly, CLOSED (K25):** "page rewritten post-recv" was never a rewrite — it was the test evidence's own hex/decimal offset bug. The K20 markers read the DHCP op at `0x842` (frame+**0x42** = 66, a zero chaddr field) while the copy lands the op byte-exactly at frame+**42** = page+`0x82A`: the kernel's `buf + 42` (decimal, correct) read 2 while the blob's `[0x403842]` and the verifier's `data_pa + 0x842` (hex 0x42 = 66) read a neighboring zero field — "the byte flips in the syscall-return window" was two reads of two different bytes 24 apart. The proof stack that pinned it: kernel-side brackets (arm-end/dispatch/next-syscall/timer), a live CR3→PML4→PT walk proving the PTE constant and correct, and a from-scratch GDB-remote watchpoint client (`scripts/k25_gdb_watch.py`) on both the direct-map and user aliases — which caught the copy loop, the post-teardown scrub, and *no writer in the window at all* (the tell that ended the ghost hunt: impossible physics means no crime). The fix: the blob and verifier read the true offsets, the page's integrity is now PART of the lane's ok gate (`t0va=2 t1=2 t2=2 verify=2`). A K26 coda: the K25 fix's own yiaddr literal (`0x838` = frame+56, two bytes short of the true `0x83A` = frame+58) slipped past the weak `!= 0` gate — caught days later by K26's data-page layout HOST TEST on its first run, and the gate is now the 10.0.2.x address-class check, not merely nonzero — and the anomaly's five-round forensic trail is in the K25 changelog — the lesson written down: when the instrumentation says "a write happened, was read back, and vanished with no writer," audit the *reader* first.

- **The attenuation/security hardening round (ADR-0031 §A+§B, ADR-0032 §A/§B/§C, ADR-0033, + the exec image quota)** — six reviewer-found holes, each reproduced red, fixed, and guarded: **(1) sigreturn frame flag forgery (ADR-0031 §A)** — a CPL=3 domain can `pushfq`/`popfq` IF=0+AC=1 and sigreturn it into its own kernel-side frame; the resume path now whitelists the saved frame's flag bits, the restored context is always preemptible, and entries never inherit AC (the entry's gated `clac`, on `ENTRY_CLAC_GATE`). **(2) the entry never runs on user flag state (ADR-0031 §B)**: `cld` right after `cli`, an explicit RFLAGS sanitize (TF|IF|DF|NT|AC cleared through the pushed slot — pinned by a new asm-pattern guard rule), a **safe IST7 `#DB` handler** (the pure `classify_debug`: a user-set TF surviving SYSCALL traps inside the entry window → clear-TF-in-the-saved-frame and resume; ring-3 traps stay the domain's own death; everything else fails CLOSED to the forensics dump), and honest per-flag measurement: FMASK reads back exactly what was written yet the kernel still self-enforces every bit (DF is cleared at the TCG transition; AC and IF are not). Blob mode 18: DF/TF/AC rogues make copy-heavy excursions — payloads byte-exact, the TF rogue dies by its own trap in either reading, the kernel never halts. **(3) spawn attenuates on EVERY axis (ADR-0032 §A)** — `DomainProfile::is_attenuation_of`, a pure, exhaustively-destructured relation (adding a field breaks the build until it's classified): mask vs the parent's LIVE mask, quota vs LIVE quota, monitor sensitivity, the Tighten tier (strictly narrower, always keeping exit), fan-out strictly below, base rights never broader — before, a `max_children=2` parent ACCEPTED `sensitivity=0`+`degraded=syscalls`+`max_children=1000`; every axis violation is now a typed reason + an escalation attempt. **(4) exec ratchets, policy by IMAGE identity (ADR-0032 §B)** — the monitor mode can never turn off across exec (once Enforce, always; `None` = inherit for unlisted images), and the policy table is keyed by a 64-bit content hash of the image bytes, never a path string, with lexical `canonicalize_path` before the registry lookup — `//bin/./x` and `/bin/../bin/x` cannot dodge a declared policy. **(5) per-frame reference counts (ADR-0032 §C)** — the shared-frame table was a linear 64-entry array that capped the WHOLE SYSTEM at 64 shared pages (any fork of a >64-page domain was refused, with the wrong error variant, and the rollback silently leaked); it is now dense per-frame counts indexed by pool frame number — O(1), u16 checked (typed Overflow), rollback = exact tree rewalk, and a 2000-page fork is host-proven. **(6) ELF entry executable + exact `e_phoff`, and the exec image quota (ADR-0033 + N2)** — mutation fuzzing found 118 accepted images whose `e_entry` pointed into a NON-executable segment (dead on the first NX fetch); now refused typed, along with `e_phoff != 64`. And every program was capped at a hard-coded 16 pages by the exec mapper — the quota is now the caller's LIVE profile quota with a pure pre-check BEFORE the point of no return (an over-quota exec answers `-ENOMEM` with the old image intact — proven live by a five-page domain exec'ing the six-page shell). All lanes re-proven: `--verify` (every marker byte-exact), q35, q35-noiommu, and the shell lane green; the persist lane hits the documented ADR-0030 flake-family timeout. The round closes with **three seeded fuzz harnesses** (round A6/ITEM 8): the syscall storm (240k hostile ops — zero panics, zero mask-widening, live), the lifecycle storm (240k spawn/fork/exec/kill/exit ops — 17.8k guaranteed-widening spawn attacks, ALL refused; the exec monitor ratchet held), and the ELF mutation fuzzer (300k mutations of the two REAL registry images — 108k accepted plans, every loader invariant re-derived and held, 192k typed refusals).
- **K22: the package manager runs INSIDE the VM — a signed package installs at CPL=3** — `/bin/pkg` is the exec registry's third citizen, linked under the `SERVICE` memory contract (a 128-page cage, an 8 MiB no_alloc stack) and carried in the kernel's SECOND 2 MiB huge page (the image that outgrew the single leaf: 119,424 B stripped beside 73,728 B of headroom). The lane: a root supervisor provisions the `pkg-mkrepo`-built signed repo (root-owned 0644 — the manager reads its anchors, never rewrites them) while `/pkg` is group-writable by the manager's gid; a ring-3 caller execve's `/bin/pkg install r1/hello` with internal nr 19; the image resolves against the Ed25519-verified index, stages, and commits through its OWN 9-syscall mask (no fork/exec/mmap/net/ipc); the kernel verifies the installed tree byte-exact. The round's found-live bugs: the entry's internal-mode hybrid mapped Linux nr 35 (nanosleep) onto SYS_NANOSLEEP, so internal `SYS_RENAME`=35 was ALWAYS hijacked into a masked nanosleep — renumbered to 36; the adapter's mkdir passed mode 0 (dirs at 0o000 — the transaction died inside its own staging tree); the no_alloc chain is really 7.26 MiB (rustc's probe-loop prologues hid 2.2 MiB frames from the static measure); `run_cli` was handed argv[0]. Gates: 10/10 host + `--verify` PASS with the `[PKG]` markers.
- **M3: writable persistence, the TTY, and a CPL=3 shell (Phase 6 + Phase 7 / ADR-0025/0030)** — the ext2 write path runs over an honest raw-image store (`mkext2-rw`), and `--verify-persist` boots the SAME disk twice: boot 1 writes `persist.txt`, boot 2 reads it back through a second vblk session (frames from the image, one branch, no shortcuts). The TTY is serial RX by interrupt with a ring and a console-in alias; PID 1 runs at CPL=3 with the init pattern (fork, orphan reparenting, a blocking `wait4(-1)` loop reaping both children — ADR-0022 D7), `list_dir` gives the shell its `ls` (v1: `getdents64(259)`), and `--verify-shell` drives the whole interactive stack green. The ELF loader + `execve` are live (the registry's `/bin/sh` and `/bin/exec-target`, image-identity-keyed policy), fork + CoW are live (mode 13's fork-with-CoW-store, and the fork/write/exit model with Copy/Promote transitions), and the timer-preemption machinery landed with its ADR-0012 environment measurement (TCG does not apply `FMASK.IF` across SYSCALL — the entry self-enforces).

- **The Linux-compatible entry, slice 1 (round S / ADR-0003 / ABI-VERSION v1)**: a domain can now speak **Linux x86_64 syscall numbers at the entry**. A per-domain ABI flag (`Internal` default | `Linux`, supervisor-declared at spawn, inherited across fork) picks the number translation — a **whitelist**, not a pass-through, running BEFORE the bounds check and the policy gate; internal ids stay the policy space, so profiles never see a Linux number. The whitelist's edge is the round's found-live discovery: Linux nr 63 is `uname` while internal 63 is EXIT — a pass-through would exit a Linux binary on `uname()` — so every unmapped nr (including all sub-64 collisions) answers `-ENOSYS`, audited on the live domain. Shape differences are honored at the arm: `pipe(2)` answers rax=read/rdx=write (the x86_64 convention), `exit_group(231)` aliases exit, `mmap(2)` demands MAP_PRIVATE|MAP_ANONYMOUS; **Slice 2 (round T) landed `open(2)`**: the Linux O_* word is translated at the SYS_OPEN arm — the access mode (RDONLY=0, WRONLY=1, RDWR=2) becomes the internal O_READ/O_WRITE bits, O_CREAT and O_TRUNC ride along, and every bit whose semantics the internal VFS cannot honor (O_EXCL, O_APPEND, O_NONBLOCK, O_DIRECTORY, O_NOFOLLOW, O_CLOEXEC) refuses `-EINVAL` — never silently dropped. **Slice 3 (round U) landed `wait4(2)`** on the ADR-0022 D7 core (`wait_process`/`exit_process` were waiting in the lib since round K): the blocking path parks with the **rip-2 re-execute image** (rip ON the syscall instruction, rax = the ORIGINAL nr from the frame's RAX slot — resume re-runs the arm; the park machinery stays ABI-blind), the child's completion wakes the parent through the waiter registry (`set_runnable`, nanosleep's own primitive), the re-executed arm consumes the child's completed-mailbox entry (frames via `free_frames_of`, then `exit_process` records the zombie) and answers the pid + the Linux wstatus word (7 << 8); WNOHANG honored, unknown option bits refuse, and a CoW-RO wstatus target answers `-EFAULT` loudly (the kernel's direct write cannot service a CoW the user's own store would). (This bullet's `execve` refusal note is history: the ELF loader landed in M3 — see the exec/persistence bullet below.) Blob mode 13 proves the whole lane from CPL=3 speaking only Linux nrs — the pipe split, a byte round-trip, EOF after the write end closes, mmap + the MAP_SHARED refusal, the uname/getpid probes, fork with a CoW child store — red (nr 22 hit internal SCHED_YIELD, zero clean exits) then green on all three QEMU lanes.

**Done and proven (M0 + M1 + Stage 1 / PR-1.1..1.4 + M2-W1/W2):**

- The full policy kernel as a library: attenuation-only syscall masks, capability generations, W^X memory policy, VFS with Unix DAC + chroot, pipes/signals/fd tables, CFS scheduling, rate-limited brokered sockets, capability-endpoint async IPC (ADR-0004), behavior monitor with graduated response. **434 tests.**
- A bootable x86_64 system, two-stage (QEMU's `-kernel` loader rejects ELF64 — discovered on the first CI boot run): a pure-asm ELF32 multiboot stub (`boot-x86_64/`) sets up identity paging and long mode, then runs the 64-bit kernel (`kernel-x86_64/`, embedded at its 2 MiB link base) over real RAM: a physical frame pool (4096 × 4 KiB at 16..32 MiB, grown for per-domain page tables in PR-1.3) behind the policy core's buddy allocator with **scrub-on-free verified by read-back**, and the M1 exit-criteria sequence running on boot: a hello domain scheduled by CFS, the monitor escalating an attacker across five windows while the healthy neighbor keeps running, and 1000 create/destroy cycles with zero frame leaks.
- **SYSCALL/SYSRET entry + ring-3 machinery (Stage 1 / PR-1.4 + M2-W2/ADR-0010 + round J)**: the GDT carries the STAR slot arithmetic (host-test-pinned), the naked SYSCALL entry (swapgs, dedicated guarded stack, 12-quadword SysV-aligned frame, TSC round-trip, the user-RSP park/restore — SYSRET reloads only RIP/RFLAGS, so the stub carries the user's stack pointer itself; hidden since PR-1.4, exposed by the first `call` in ring-3 history), the shared policy gate in `syscall::gate` (one door for kernel-resident and ring-3 domains, full-width nr bounds check), SYS_WRITE with per-page user-pointer validation, and the CPL3-fault record/resume path. **Ring-3 isolation is fully live**: the eight-run sequence (hello / NX exec / kernel-VA read / forged syscall / tail-of-page + crossing writes / live-monitor quarantine / audit-only / the file lifecycle) boots green in QEMU TCG and `boot.sh --verify` asserts every marker — the earlier "environment-blocked" verdict was retired when its four root causes (stray IRQ at the IF boundary, mirror-inverted stub offsets, the launch/resume register hole, an `iretq` regression) were all found and fixed locally (ADR-0010).
- **The ring-3 file lifecycle (round J)**: OPEN, READ, WRITE, CLOSE, PIPE and DUP execute on the LIVE lib kernel — marshaled through the host-tested `sysabi` layer (the open-flag decoding, the complete SysError→errno table, the pipe fd-pair packing) and run by `Kernel::execute` on the same state the monitor reads, after the runtime's own gate pass. The stdio triplet (fds 0/1/2) is reserved at spawn Unix-style so the console device alias behind fd 1 can never collide with a real descriptor; user pointers are validated page-by-page through the domain's own tables in BOTH directions (the copy-out primitive and the page-check-as-you-go path reader are new), and the `ring3-files` blob proves the whole dance from CPL=3 with in-blob verification: pipe round-trip, dup keeping a pipe end alive past its original's close, file create/write/read-back through an independent cursor, and the -EBADF/-ENOENT refusals. The register tables — v0.4's internal surface and v1's Linux entry — are specified in `docs/ABI-VERSION.md`.
- **Per-domain page tables (Stage 1 / PR-1.3)**: the lib's ten-check memory policy is the gate, and its decisions become hardware — `map_region` policy-checks first, then backs every accepted page with a scrubbed pool frame and a live PTE (U set, NX unless executable, guard gaps as **absent** pages). Two domains, disjoint tables, the same VA resolving to different frames — proven live in QEMU, including an NX exec fault that resumes cleanly and a guard-gap read that faults with CR2 naming the page. Pool grows to 4096 frames (16..32 MiB); `mm` stays unsafe-free. **11 new host tests** pin the walk, the policy gating, and unmap/rollback.
- **Higher-half kernel + direct map (Stage 1 / PR-1.2, ADR-0002)**: the kernel links at `0xFFFFFFFF80000000` (loaded at PA 2 MiB via a linker `AT()` + objcopy-by-LMA split), the stub maps three windows before entry — kernel image, direct map (`0xFFFF888000000000`+PA, RW, never X), and a bring-up identity window the kernel **tears down and proves dead** right after entry. Guarded kernel stacks (absent-PTE guard pages, pool-backed, scrub-on-free) fault for real when run over; per-CPU state is anchored at the GS base. The `mm` layer itself is unsafe-free by design. **7 new host tests** pin the translation and slot arithmetic.
- **Exception machinery (Stage 1 / PR-1.1)**: a kernel-owned GDT/TSS/IDT with a uniform exception frame, IST stacks for `#DF/#NMI/#MC/#SS`, and a live negative test — the boot forces a hardware `#DE` and the dispatch prints the diagnosis and the selftest marker before powering off. Every fault from here on is diagnosed, not a silent hang. **11 new host tests pin the descriptor/frame encodings, including the boot-stub GDT literals as an ABI contract.**
- Unsafe policy enforced by machine, not convention: the policy core is `forbid(unsafe_code)`; the kernel is `deny(unsafe_code)` with a five-entry allowlist (`arch/`, `boot/`, `hw.rs`, `memops.rs`, `sched/`), every item carrying a `SAFETY` note, and a **ratchet** (`scripts/unsafe-count.txt`, baseline 78) that fails CI if the count grows without an ADR.

**Not yet — the explicit P2 list (no aspiration, only named work):**

1. **The syscall-entry tick seam, at the stub level**: SYSCALL enters CPL0 with IF=1
   (this QEMU ignores FMASK.IF), so a preempt tick landing between `swapgs` and `cli`
   is a CPL0-origin interrupt frame pushed on the USER stack. The long syscall-heavy
   steps pause ticks around their runs today (the ADR-0019 window discipline, scaled);
   the real fix is the IDT stubs switching to the kernel stack for CPL0-origin
   external vectors (named by the tick guard's halt telemetry: `rip=syscall_entry+2`).
2. **The ext2 indirect-block read**: files above 12 KiB cannot ride the repo path
   (direct blocks only) — a bigger userland program than the netcat client needs it.
3. **A hosted libc (musl)**: the gcc userland is freestanding `-nostdlib`, and the
   syscall surface it needs (the v1 Linux ABI lane) is live but far from complete.
4. **SMP**: single CPU only; all driver domains are lane-green but the scheduler,
   the frame pool and the broker tables are single-CPU shapes.
5. **NVMe and AHCI at ring 3**: the three NIC/disk driver migrations are done
   (virtio-blk, virtio-net, e1000 — each a CPL=3 domain on its OWN rings); NVMe and
   AHCI still run ring-0 proofs.
6. **aarch64**: the HAL seam is designed (ADR-0011) and CI cross-arch builds the
   policy core, but no second boot exists.
7. **KVM and real hardware**: never run — this sandbox is TCG-only.

Live and lane-proven (the gaps the list above is NOT about): the ring-3 syscall
surface (the file family, mmap/munmap, fork/exec/CoW, the wait family, signals,
chroot, and the brokered NET pair), the full TCP/IP story twice over (the kernel's
own stack driving TLS 1.3 to a real OpenSSL server, and the P1-1 ring-3 netstack
service with its gcc client against the host's echo servers), timer preemption, the
ELF loader with image-identity policy, ext2 write persistence and the TTY + shell
lanes, the package manager in-VM (four lifecycle rounds with real binaries), and the
driver stack (rng, wdt, console, balloon, virtio-net, e1000, NVMe, AHCI + ext2/FAT32,
xHCI + the USB keyboard, the GFX console, the RTC).

## The architecture in one line

> Unix gave us clarity, separation of concerns and stable interfaces; AegisOS adds one unbreakable rule on top: **attenuation-only privileges** — there is no code path anywhere in the kernel that can widen a live domain's syscall mask.

## Quick start

```bash
./boot.sh                 # build the kernel and boot it in QEMU (needs qemu-system-x86)
./boot.sh --verify        # ...and assert EVERY marker: M1 + selftests + ring-3 + M3 (persist-excluded)
./boot.sh --verify-q35    # the same machine on the q35 chipset
./boot.sh --verify-q35-noiommu   # q35 with the IOMMU off (the SMAP/NXE quirks differ)
./boot.sh --verify-persist  # TWO boots, one disk: boot 1 writes persist.txt, boot 2 reads it back
./boot.sh --verify-shell    # PID 1 + the TTY + the shell's ls/exec round-trip

cargo test                       # 470 policy-core tests
cargo test -p aegis-kernel       # 320 host tests: boot + arch/mm/gate/ring-3/sysabi/file-ABI/elf/netdata/ext2 encodings
cargo build --target thumbv7em-none-eabihf   # the core still builds for bare-metal ARM
```

What the boot log shows (CI greps exactly these): the GDT/TSS/IDT going live, the higher-half switch (`[MM ] higher-half ok`, identity window torn down), multiboot memory validation, the frame pool claim, the guard-gap policy rejecting an adjacent mapping **live**, CFS slices, `Hello from AegisOS domain 1`, the five-window escalation `55 → 50 → 37 → 80 → 80` ending in quarantine with the neighbor healthy, `leaked-frames=0`, `scrub-verified=yes`, a single `M1-EXIT-CRITERIA: PASS` verdict line — then the selftests: a forced hardware `#DE` diagnosed and **returned from** (the unwind path Ring-3 signals will use); two domains with disjoint page tables — the same VA resolving to different frames, an **NX exec fault that resumes** (W^X enforced by the MMU), an RX page actually executing, and a policy guard-gap page faulting on read (`[MM ] per-domain tables: 2 domains, W^X + guards live`); a guarded kernel stack allocated/mapped/cross-viewed/freed-scrubbed; and a final write through a stack guard page → `#PF` → clean poweroff.

## What's inside

| Area | Module | Linux analog | Key invariants |
|---|---|---|---|
| Syscall gate | `syscall` | syscall table + seccomp | `u64` bitmask, O(1) AND+bit-test; masks only ever attenuate |
| Capabilities | `capability` | capabilities(7) | Generation counters make use-after-revoke impossible |
| Memory policy | `memory` | mmap + W^X | NULL/wraparound/overlap rejection, guard gaps, quotas, scrub accounting |
| Page frames | `buddy` | buddy allocator | Power-of-two blocks, split on alloc, coalesce on free |
| Boot + frames | `kernel-x86_64` | boot/paging | Multiboot → long mode → identity map; real pool, owner tracking, scrub-on-free |
| CPU tables + exceptions | `kernel-x86_64/src/arch` | GDT/TSS/IDT | Uniform frame, IST for #DF/#NMI/#MC/#SS (not #PF), DPL-0 gates, stub GDT = boot ABI |
| Memory layout | `kernel-x86_64/src/mm` | higher-half + direct map | Kernel at 0xFFFFFFFF80000000, direct map RW no-X, guarded stacks (absent-PTE guards), identity window torn down — unsafe-free |
| Filesystem | `vfs` | VFS + DAC + chroot(2) | owner/group/other `rwx`, execute-to-traverse, `..` clamped at chroot root |
| Descriptors | `fd` | open file table | lowest-free allocation, dup2 semantics |
| Pipes | `pipe` | pipe(2) | bounded ring, short I/O, EOF, EPIPE, dup-aware end refcounts |
| Signals | `signal` | signal(7) | pending/blocked masks, unblockable SIGKILL/SIGSTOP |
| Scheduling | `sched` | CFS | vruntime + the real Linux nice→weight table |
| Network | `net` | sockets + tc/tbf | brokered sockets, per-domain token buckets |
| Profiles | `profile` | service types | service / parser / driver / plugin / netd — least privilege |
| Monitoring | `monitor` + `response` | auditd/ML security | integer risk score, hysteresis, Log → Tighten → Quarantine |
| Telemetry | `ringbuf` | relay/perf rings | SPSC, drop-and-count when full — never blocks |

## The syscall pipeline

```text
            ┌──────────────────────────────────────────────────┐
            │  Kernel::syscall(domain, request)                │
            └───────────────┬──────────────────────────────────┘
                            │  1. GATE (deterministic fast path)
                            │     bounds check → quarantine check
                            │     → mask bit test → saturating counters
                            ▼
            allowed? ── no ──► Masked / Quarantined / BadSyscall
                            │  2. EXECUTE (Linux-like state)
                            ▼
     VFS (Unix perms, chroot) │ fd table │ pipes (refcounted ends)
     signals (kill rules)     │ sockets + token buckets │ scheduler
                            │  3. TELEMETRY
                            ▼
     SecurityEvent ring → behavior monitor (slow path, per window)
                       → Log → Tighten → Quarantine (EXIT-only, terminal)
```

On the booted kernel, all of this sits on real memory: `_start` → long mode → frame pool → `Kernel::new()` → the M1 sequence (see `kernel-x86_64/src/kmain.rs`).

## Behavior monitor (the security layer)

Five real signals from the fast path — denied ratio, faults, capability-escalation attempts, out-of-profile syscall bits, rate spikes — feed an integer-only risk score (u128 intermediates, deterministic, overflow-proof). Graduated response with anti-flap: a single bad window never escalates (hysteresis), reported scores decay, tightening keeps the app alive (it only drops spawn/net/ioctl/mmap/open), quarantine is terminal and passes only `SYS_EXIT`. If the monitor's state table fills, it degrades to logging — but instant quarantine at score ≥ 95 still fires. Fail-safe, not fail-open. On boot, the proven five-window escalation scenario runs live and its verdicts are printed.

Docs: [`docs/ROADMAP.md`](docs/ROADMAP.md) (roadmap v2: the eight stages to a usable Unix-like core) · [`docs/STAGE1-PR-PLAN.md`](docs/STAGE1-PR-PLAN.md) (the current stage, PR by PR) · [`docs/arch/exceptions.md`](docs/arch/exceptions.md) (PR-1.1 component doc) · [`docs/adr/`](docs/adr/) (architecture decision records) · [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) · [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) · [`docs/M1-PLAN.md`](docs/M1-PLAN.md) · [`CONTRIBUTING.md`](CONTRIBUTING.md) (the PR contract) · [`docs/ABI-VERSION.md`](docs/ABI-VERSION.md)

## Roadmap position

The master plan is now [`docs/GAP-ANALYSIS-v2.md`](docs/GAP-ANALYSIS-v2.md) (phases to the full production brief, ≈28 weeks of the current cadence); [`docs/ROADMAP.md`](docs/ROADMAP.md) keeps the stage detail and [`docs/M2-PLAN.md`](docs/M2-PLAN.md) the current milestone. **Current position: Stage 1 + M2 + the M3 security-hardening round complete (ADR-0031 flag hygiene live in the entry and the sigreturn path, ADR-0032 attenuation as a checked relation — spawn/exec/fork, ADR-0033 ELF hardening, persistence + TTY + shell + exec/ELF live); next: the fuzz harnesses (syscall storm / lifecycle / ELF mutations), then real networking and the aarch64 bring-up.** Multi-architecture is designed (ADR-0011: HAL/BSP seam) and enforced by CI cross-arch builds of the policy core.

## Repository layout

```text
boot-x86_64/              stage 1: the ELF32 multiboot boot stub (pure asm)
├── stub.S                  GDT, identity paging, long mode, kernel handoff
└── stub.ld                 1 MiB stub + kernel blob at its 2 MiB link base
kernel-x86_64/            stage 2: the bootable M1 kernel (x86_64)
├── linker.ld               2 MiB link base, pinned entry, 256 KiB stack
├── build.rs                -T linker script only for the bare-metal target
└── src/
    ├── arch/              UNSAFE ALLOWLIST (ADR-0005): GDT/TSS/IDT + exception entry
    ├── boot/               UNSAFE ALLOWLIST: naked 64-bit entry
    ├── hw.rs               UNSAFE ALLOWLIST: port I/O, rdtsc, cr2, poweroff
    ├── memops.rs           UNSAFE ALLOWLIST: volatile memory + scrub
    ├── serial.rs           COM1 output (safe, over hw primitives)
    ├── multiboot.rs        pure multiboot-info parsing (host-tested)
    ├── frames.rs           FramePool: owners + scrub over the core buddy
    ├── runtime.rs          the M1 sequence (host-tested, callback-driven)
    └── kmain.rs            live boot: validate → claim → run → verdict
src/                      the policy core (this is the aegis-os crate)
├── syscall.rs    capability.rs    memory.rs    buddy.rs
├── vfs.rs        fd.rs            pipe.rs     signal.rs
├── sched.rs      net.rs           profile.rs  domain.rs
├── monitor.rs    response.rs      ringbuf.rs  sys.rs
└── lib.rs        Kernel assembly (domains, VFS, scheduler, monitor)
tests/
├── integration.rs   security scenarios (escalation, isolation, telemetry)
└── linux_like.rs    Linux-semantics scenarios (VFS/pipe/signal/sched/net)
boot.sh                 one command: build + boot (+ --verify proof mode)
scripts/check_unsafe.sh the unsafe-allowlist policy + ratchet (CI-enforced)
docs/                   roadmap, stage plans, ADRs, component docs
```

## License

MIT — see [LICENSE](LICENSE).
