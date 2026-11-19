# Changelog

All notable changes to AegisOS. Format: [Keep a Changelog](https://keepachangelog.com/), versions: [SemVer](https://semver.org/).

## [0.2.0] — 2026-11-19 — "It boots" (M1)

The project is no longer just a library: AegisOS now **boots on QEMU** and
runs its M1 exit-criteria sequence on real physical memory, with CI
proving it on every push.

### Added — bootable kernel (`kernel-x86_64/`, new workspace member)

- Multiboot v1 bring-up: 32-bit entry, own GDT, identity page tables
  (1 GiB, 2 MiB pages), PAE → EFER.LME → CR0.PG long-mode transition,
  64-bit handoff to `kmain` with the boot TSC stamped at the first
  instruction.
- Real frame pool: 256 × 4 KiB at physical 16 MiB, claimed only after
  multiboot `mem_upper` validation, managed by the **existing** policy-core
  buddy allocator (the `Kernel.frames` instance), with per-frame ownership
  tracking and **scrub-on-free verified by read-back**.
- The M1 boot sequence: hello domain (guard-gap policy rejecting an
  adjacent mapping live, 3 real backed frames, CFS slices), the proven
  five-window monitor escalation (55 → 50 → 37 → 80 → 80, quarantine,
  healthy neighbor unaffected), supervised cleanup, and a 1000-cycle
  create/destroy stress asserting zero frame leaks. Verdict printed as a
  single `M1-EXIT-CRITERIA` line; clean QEMU poweroff.
- `boot.sh` (one command to build+boot; `--verify` asserts the exit
  criteria and is what CI runs).
- Unsafe policy, machine-enforced: kernel is `deny(unsafe_code)` with a
  documented three-module allowlist (`boot/`, `hw.rs`, `memops.rs`), each
  item carrying a `SAFETY` note; `scripts/check_unsafe.sh` fails CI on
  violations.

### Added — policy core

- `Kernel::destroy_domain`: releases pipe ends (dup-aware), brokered
  socket, rate bucket, scheduler registration, and the table slot; works
  on quarantined domains (the supervised-respawn removal path). Files it
  created persist (Unix semantics).
- Public `Kernel::domain_mut` accessor for supervisors and the kernel
  runtime (all Domain fields were already public).

### Changed

- Repository is now a Cargo workspace (`kernel-x86_64/` member;
  `default-members = ["."]` keeps root `cargo test` scoped to the core).
- CI expanded from 3 to 7 jobs: core tests, kernel host tests (the same
  M1 sequence logic without an emulator), ARM no_std build, kernel ELF
  build with ELF sanity checks, **QEMU boot test**, dependency audit
  (workspace-wide), and the unsafe-policy allowlist check.
- Docs: README rewritten around the real boot status; new
  `docs/SECURITY-MODEL.md` one-pager; `docs/M1-PLAN.md` (assessment,
  design, exit-criteria mapping); ARCHITECTURE/ROADMAP updated.

### Numbers

- Tests: 196 (policy core) + 23 (kernel host) = **219**, all green.
- Kernel ELF: ~53 KiB release; kernel image + bss + stack end ≈ 0x14F010,
  far below the 8 MiB safety line and the 16 MiB pool.
- Boot time target (< 300 ms in QEMU) is measured and reported by the CI
  boot job (wall-clock of the full QEMU run, startup included).

## [0.1.0] — 2026-11-19 — Policy kernel M0 + Linux semantics

- Attenuation-only syscall masks, capability generations, ten-check memory
  policy, VFS with Unix DAC + chroot, fd tables, refcounted pipes,
  POSIX signals, CFS scheduling (real Linux weight table), buddy
  allocator, brokered rate-limited sockets, executing syscall layer
  (gate → execute), behavior monitor with graduated response, SPSC
  telemetry rings.
- 191 tests; zero dependencies; `forbid(unsafe_code)`; no_std proven on
  thumbv7em-none-eabihf.
