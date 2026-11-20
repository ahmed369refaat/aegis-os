# M1 — Boot + Physical Memory: Assessment and Implementation Plan

> Status: **EXECUTED** (v0.2.0). This document is the mile-zero assessment
> (what was solid, what was missing), the design decisions for M1, the
> ordered implementation plan, the risks, and the exact mapping from the
> M1 exit criteria to artifacts that prove them. Results are recorded in
> §7.
>
> Working rules honored here: no jumping ahead to M2+; every claim below is
> either already covered by a passing test or is listed as unverified until
> its verification artifact exists.

## 1. Assessment of the current state (M0, commit `683cad4`)

### 1.1 What is solid (and proven by which test)

| Area | State | Proof |
|---|---|---|
| Attenuation-only syscall masks | Solid — the only mask mutation anywhere is intersection; derivation that would widen is rejected | `syscall` unit tests; profile cross-rules tests |
| Capability table with generations | Solid — stale handles after revoke/slot-reuse are rejected; escalation attempts are surfaced as a monitor signal | `capability` tests |
| Memory **policy** (W^X, guard gaps, quotas, wraparound/NULL rejection, scrub accounting) | Solid as *policy* — `AddressSpace::map` runs ten ordered checks | `memory` tests (14), boundary cases at `usize::MAX` |
| Buddy allocator | Solid as *bookkeeping* — split/coalesce/OOM reporting over 256 frame indices | `buddy` tests (13) |
| VFS + Unix DAC + chroot | Solid | `vfs` tests (19) + `linux_like` integration |
| Pipes / signals / fd tables | Solid | `pipe` (13), `signal` (11), `fd` (8) + integration |
| CFS scheduler | Solid (nice→weight table, weighted vruntime, starvation-free) | `sched` tests (12) + integration |
| Rate-limited brokered sockets | Solid | `net` tests (11) + integration |
| Behavior monitor + graduated response | Solid (integer scoring, hysteresis, decay, sensitivity, fail-safe) | `monitor` (17), `response` (6) + escalation scenario |
| Executing syscall layer (gate → execute) | Solid | `sys` + `linux_like` |
| Supply chain | Zero external dependencies; `#![forbid(unsafe_code)]` enforced in CI; no_std proven on `thumbv7em-none-eabihf` | CI jobs `no-deps`, `no-std` |

**Total: 191 tests green, zero warnings.**

### 1.2 What is missing for M1 (the honest list)

1. **It is a library, not a system.** Nothing boots: no binary crate, no
   entry point, no linker script, no boot protocol, no target.
2. **No hardware access layer at all.** No serial output, no register
   access, no timer read, no clean machine exit. The lib cannot even contain
   such code (`forbid(unsafe_code)` + no_std by design — that is correct and
   stays).
3. **All memory is bookkeeping, not memory.** `AddressSpace` regions are
   policy records with no backing; the buddy allocator manages frame
   *indices* with no physical memory behind them; "scrub" is a counter, not
   zeroing; "guard pages" are policy gaps, not unmapped entries.
4. **No domain lifecycle.** `Kernel` can create domains but not destroy
   them, so create/destroy stress cycles are impossible without a change.
5. **No measurement.** No boot timing, no boot-time self-checks, no CI proof
   that the system boots.
6. **Docs claim M0.** README/ARCHITECTURE/ROADMAP must reflect exactly what
   boots and what does not, or the project overclaims.

### 1.3 Environment reality (stated plainly)

The development sandbox used for this work has **no QEMU** and no way to
install it (no root). It does have: rustc 1.100 + the `x86_64-unknown-none`
target, gcc/binutils for linking, and network (GitHub push/pull works).

Consequences for verification, in order of strength:

- **Build proof (local):** the kernel ELF compiles and links locally for
  `x86_64-unknown-none`; `objdump` checks (entry symbol, multiboot header in
  the first 8 KiB, load addresses).
- **Logic proof (local, host tests):** everything except raw asm/port-I/O —
  frame pool, scrub-on-free over a real memory buffer, multiboot parsing,
  the entire M1 boot sequence (hello domain, monitor demo, 1000-cycle
  create/destroy, leak and scrub assertions) — is written as host-testable
  modules and runs under `cargo test -p aegis-kernel`.
- **Boot proof (CI):** GitHub Actions `ubuntu-latest` runners install QEMU
  via apt; a CI job boots the kernel, greps the serial log for the M1
  markers, and fails the build if any is missing. The repository's CI status
  is the durable, public boot proof.

## 2. M1 scope decisions

| Decision | Choice | Rationale |
|---|---|---|
| First target | x86_64 via QEMU `-kernel` (multiboot v1) | No bootloader dependency; a 20-line header instead of a crate; aarch64 follows as a second target once x86_64 exit criteria are green |
| Repository layout | Root stays the `aegis-os` lib; add `kernel-x86_64/` bin crate as a workspace member with a path dependency | Smallest diff that preserves all 191 tests; still zero *external* dependencies; full restructuring deferred until there is more to reorganize |
| unsafe policy | Lib keeps `forbid(unsafe_code)`. Kernel crate is `#![deny(unsafe_code)]` with `#![allow(unsafe_code)]` **only** in `boot/` (entry asm, page tables) and `hw.rs` (port I/O, rdtsc, shutdown). Every block documented. CI enforces the allowlist | Matches "unsafe isolated to boot/paging only, heavily documented" — and makes violations a build failure, not a convention |
| Frame pool size | 256 × 4 KiB = 1 MiB at physical 16 MiB..17 MiB, managed by the **existing, unmodified** buddy allocator inside `Kernel` | M1 needs correctness, not capacity; the pool is real physical memory, validated against the multiboot `mem_upper`. Const-generic scaling is planned for M2 (32–64 domains) |
| Scrubbing | On every frame free: 4 KiB zeroed by volatile writes, then sampled read-back verification on the boot path | "Actual page scrubbing" made literal and self-checked |
| Guard pages | M1 enforces the existing policy gap (adjacent mapping rejected live at boot) and leaves the gap page physically unallocated. Hardware guard enforcement (unmapped entries in per-domain tables) is **M2** — stated in README, not hidden | Honest scope: no per-domain page tables exist yet |
| Domain model at M1 | Domains are kernel-resident objects (lib `Domain`), scheduled by the lib CFS scheduler; a "hello domain" is a real domain whose region mapping passes the ten policy checks and whose pages come from the pool. Ring-3 execution + per-domain address spaces are **M2** | M1 exit criteria say "runs at least one domain"; this runs one for real, with real frames, and the docs say exactly where the isolation boundary currently ends |
| Monitor on boot | A compact replay of the proven escalation scenario (Log → Tighten ×3 → Quarantine across five audit windows) runs on the booted kernel | It exercises only M0 code on the live system; it is not new M4 work |
| Boot timing | TSC cycles from `_start` to end-of-init printed by the kernel; wall-clock of the whole QEMU run measured by the runner (QEMU startup included — stated with the number) | Two independent measures, no overclaim about TSC calibration in TCG |

## 3. Design

### 3.1 Boot path (x86_64)

**Discovered constraint (first CI boot run):** QEMU's `-kernel` multiboot
loader **rejects ELF64 outright** (`Cannot load x86-64 image, give a 32bit
one`). The boot is therefore **two-stage**:

```text
QEMU -kernel aegis-boot.elf   (ELF32 multiboot v1 container, -machine pc)
  └─ stage 1 — boot-x86_64/stub.S (pure asm, no logic, ~150 lines)
      loaded at 1 MiB, entered in 32-bit protected mode (EAX=0x2BADB002)
      └─ stash multiboot regs + TSC, own GDT, stub stack
      └─ build identity page tables for the first 1 GiB (2 MiB pages)
      └─ PAE → CR3 → EFER.LME → CR0.PG → far jump to 64-bit CS
      └─ stage the handoff on the stack (the i386 assembler cannot emit
         x86-64 relocations, so the 64-bit section is relocation-free):
         RDI=magic, RSI=info, RDX=TSC, RCX=kernel entry
  └─ stage 2 — the 64-bit kernel (ELF64, linked at 2 MiB)
      embedded in the stub image at its link base (.incbin of the flat
      binary — no copying), entered via aegis_entry_64 (naked asm):
      └─ zero .bss, store the boot TSC, switch to the kernel stack
      └─ kmain: serial → multiboot parse → pool claim+scrub
         → hello domain → monitor demo → 1000-cycle stress
         → leak/scrub assertions → exit-criteria line → poweroff
```

The stub is also plain multiboot v1, so GRUB can boot the same image on
real hardware. Identity map means link address == physical address
everywhere; the pool at 16 MiB is directly writable. The kernel entry
address is injected into the stub at link time
(`ld --defsym=kernel_entry=<addr>` read from the kernel ELF header), so
nothing depends on address conventions.
- Poweroff via the QEMU ACPI port `0x604` (with `0xB004` fallback), so the
  CI job gets a clean exit and can time the run.
- Panic handler prints and halts — a boot failure is visible in the log.

### 3.2 Memory map (M1)

| Range | Size | Use |
|---|---|---|
| 0x100000 (1 MiB) … `_kernel_end` | ~1–2 MiB | kernel image + .bss (page tables, 256 KiB boot stack) |
| 0x1000000 (16 MiB) … 0x1100000 | 1 MiB | **frame pool**: 256 × 4 KiB, claimed after checking multiboot `mem_upper`, scrubbed before first use |
| above 17 MiB | — | untouched in M1 |

### 3.3 Frame pool wiring

```text
FramePool (kernel, safe code)
 ├─ base_pa, scrub: fn(u64), owner: [Option<u32>; 256]
 ├─ alloc_for(&mut Kernel.frames, owner) → buddy.alloc(0) → PA + owner tag
 ├─ free(buddy, pa, owner)   → scrub(4 KiB) → buddy.free
 └─ free_all_owned(buddy, owner) → destroy path
```

The buddy allocator is **the `Kernel.frames` field of the existing lib** —
the same instance the syscall layer uses; the kernel adds only ownership
tracking and the physical scrub on top. `Kernel::destroy_domain` (new,
small, tested) releases the domain's fds (and thus pipe ends), closes its
socket, drops its bucket, unregisters it from the scheduler, and frees the
slot.

### 3.4 What each M1 exit criterion maps to

| Exit criterion | Artifact that proves it |
|---|---|
| Boots reliably | CI job `boot-test`: QEMU boot on ubuntu-latest, marker grep, ×3 consecutive runs locally-equivalent (CI reruns on every push); ELF build check in CI |
| Runs a hello domain | Boot log: domain created (service profile), region mapped through the ten policy checks, frames backed from the pool, slices handed out by the CFS scheduler, `Hello from AegisOS` line |
| Zero frame leaks after 1000 create/destroy cycles | In-kernel stress: 1000 × (create → map 2 pages → back 2 frames → destroy → scrub+free), then `frames_in_use == 0`, `frames_free == 256`, owner map empty — printed as `LEAKS: 0`; the same logic runs as a host test (`cargo test -p aegis-kernel`) |
| Scrubbing actually zeroes | freed-frame read-back verification on boot + host test over a real buffer |
| Boot < 300 ms (QEMU) | Wall-clock measured and printed by the CI boot job (QEMU process time, TCG); kernel-internal TSC cycles printed alongside |
| All existing tests still pass | CI job `test` (191 → grows with `destroy_domain` tests); `no-std` ARM job unchanged |

## 4. Ordered implementation plan

1. **This document** (`docs/M1-PLAN.md`) — assessment, decisions, plan.
2. **Lib: `Kernel::destroy_domain` + public `domain`/`domain_mut` accessors**
   — small, fully unit-tested; unblocks create/destroy cycles. No existing
   invariant touched.
3. **Workspace + kernel skeleton that links**: root `[workspace]`,
   `kernel-x86_64/` crate, `linker.ld`, `build.rs` (emits `-T` only for the
   bare-metal target), multiboot header + 32-bit entry + GDT + long-mode
   trampoline + identity page tables + serial + panic handler. Exit: ELF
   builds locally, `objdump` shows `_start` and the multiboot magic within
   the first 8 KiB.
4. **Host-testable core**: `strutil` (decimal/hex formatting),
   `memops` (volatile read/write/scrub — the only memory-unsafe primitive,
   allowlisted), `multiboot` (pure parser), `frames` (`FramePool`), all with
   host unit tests.
5. **M1 runtime** (`runtime.rs`): hello-domain sequence, CFS slice loop,
   monitor demo (five windows), 1000-cycle stress with leak/scrub
   assertions — every function takes an output callback so the identical
   code runs on boot and under host tests.
6. **`kmain.rs`**: boot sequence, exit-criteria line, TSC report, QEMU
   poweroff.
7. **`boot.sh`** (one command: build + boot; `--verify` mode greps markers
   and exits nonzero on failure) and **CI**: keep `test`/`no-std`/`no-deps`;
   add `kernel-tests` (host), `kernel-build` (ELF), `boot-test` (QEMU);
   upgrade the unsafe check to the allowlist script.
8. **Docs + release**: README (real boot status + quickstart),
   ARCHITECTURE (boot layer), ROADMAP (M1 checked off with measured
   numbers), SECURITY-MODEL.md one-pager, CHANGELOG.md, version 0.2.0, tag.

## 5. Risks

| Risk | Mitigation |
|---|---|
| No local QEMU — boot bugs surface only in CI | Keep asm minimal and battle-tested (classic multiboot+long-mode sequence); all non-asm logic host-tested; CI boot job prints the full serial log on failure for debugging |
| gcc default-PIE link breakage for the kernel | Explicit `-no-pie`/`-nostdlib` link args as needed (iterating locally where linking **is** verifiable); `relocation-model=static` |
| QEMU TSC semantics under TCG make cycle counts misleading | Report cycles *and* runner wall-clock; never convert cycles to ms without calibration (deferred; not needed for the criterion) |
| `.bss` not zeroed by a loader | QEMU's multiboot loader zeroes `p_memsz`; additionally, every static the boot depends on is explicitly initialized before use; page tables are zeroed then filled by `setup_page_tables` |
| Kernel struct too large for the boot stack | 256 KiB boot stack in the linker script; `Kernel` measured (~tens of KiB) fits with margin |
| `0x604` poweroff varies by machine model | CI pins `-machine pc`; kernel tries `0x604` then `0xB004`, then halts (timeout still yields the log) |
| Scope creep toward M2 (per-domain page tables, ring 3, aarch64) | Explicitly deferred in §2; PRs that add them before M1 exit are out of scope |

## 6. Explicitly deferred (do not do in M1)

Ring-3 user domains, per-domain page tables and hardware guard enforcement,
preemption/timers, IPC, aarch64 target, raising `MAX_DOMAINS`/`FRAME_COUNT`
(const-generic buddy), virtio devices, real filesystems. Each has its
milestone; M1 ends when §3.4 is proven.

## 7. Execution results (v0.2.0)

| Item | Result |
|---|---|
| Kernel ELF | Builds clean: 53 KiB release, entry `_start` @ 0x100010, multiboot header verified at file offset 0x1000 (`02 b0 ad 1b …`), image+bss+stack end 0x14F010 (below the 8 MiB ASSERT, far below the 16 MiB pool) |
| Policy-core tests | 196 green (180 unit + 16 integration), zero warnings — including 5 new `destroy_domain` tests |
| Kernel host tests | 23 green across 3 consecutive runs (frame pool + scrub read-back, multiboot parsing, formatting, the full M1 sequence, monitor neighbor-isolation, leak observability) — the identical code path `kmain` runs |
| Unsafe policy | `scripts/check_unsafe.sh` PASS: zero unsafe in the core; kernel unsafe only in `boot/`, `hw.rs`, `memops.rs` |
| Exit criteria | In-kernel verdict line `M1-EXIT-CRITERIA: PASS … leaked-frames=0 … scrub-verified=yes … monitor-quarantined=yes`; CI `boot-test` boots QEMU and asserts it; `kernel-build` asserts the ELF structure |
| Boot time | **Measured: 0.21 s wall-clock for the full QEMU run (startup included) — under the 300 ms target**; kernel-internal 47,289,557 TSC cycles entry→M1-complete (first green boot run: f470ea9) |
| Deviations from plan | aarch64 explicitly deferred (x86_64 first per the plan's own decision table); boot entropy deferred to M2 (no consumer yet); `Kernel::destroy_domain` added to the core (planned in §4 step 2) |
| First CI boot run | **Failed** with `qemu: Cannot load x86-64 image, give a 32bit one` — QEMU's multiboot loader is ELF32-only. Fixed with the two-stage ELF32 stub design (§3.1); the failure and fix are kept here on purpose: it is exactly the kind of claim-vs-reality gap this plan exists to close |

**What is still NOT claimed (re-stated):** ring-3 execution, per-domain
page tables, preemption, IPC, devices. M1's domains are kernel-resident
objects with policy-checked mappings and real tracked frames; the
hardware isolation boundary is M2 work.
