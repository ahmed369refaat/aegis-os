# Capacity: the measured limits (K20, P0-1)

Every "toy limit" in the policy core is a fixed-size array embedded in
`Kernel<N>`, and the bootable kernel keeps its `Kernel<4096>` as a kmain
stack local. That makes one number the budget everything else must fit
in: `size_of::<Kernel<4096>>()`. This document records the limits, the
measured cost of each raise, the boot marker that proves the edges, and
the limits that were deliberately NOT raised.

## The measured state

Measured by `tests/capacity_accounting.rs` (host `size_of`, printed with
`--nocapture`; the test asserts the budget):

| Component | before | after | note |
|---|---|---|---|
| `Kernel<4096>` | 216.0 KiB | 455.2 KiB | the budget number |
| `Domain` | 2688 B | 3392 B | caps 32 × 24 B + fds 32 × 20 B, inline |
| `Vfs` | 68.3 KiB | 140.5 KiB | 128 inodes × ~1.1 KiB (inline data) |
| `EndpointTable` | 2.8 KiB | 35.0 KiB | 32 endpoints, each with a 1 KiB pipe ring |
| `Scheduler` | 264 B | 2056 B | 64 entities × 32 B |
| `ProcTable` | 516 B | 1028 B | 64 metas |
| `FdTable` (per domain) | 320 B | 640 B | inside `Domain` above |
| `CapabilityTable` (per domain) | 384 B | 768 B | inside `Domain` above |

## The limits

| Limit | before → after | where | why the new number |
|---|---|---|---|
| `MAX_DOMAINS` | 32 → 64 | `src/lib.rs` | init + shell + a driver domain per device class + a service pool + the fork-bomb guard, without the table being the story |
| `MAX_PROCS`, `MAX_MONITORED` | = domains | `src/proc.rs`, `src/monitor.rs` | they track the domain table |
| `MAX_CAPABILITIES` | 16 → 32 | `src/capability.rs` | a real domain holds caps for its device, endpoints, grants and derived children |
| `MAX_ENDPOINTS` | 8 → 32 | `src/ipc.rs` | one endpoint per service domain plus pipe pairs, in a 64-domain system |
| `IPC_MAX_MSG_BYTES` | 64 → 256 | `src/ipc.rs` | a real request (a path, a small header block) fits; `CHANNEL_CAPACITY` (the pipe ring) scales to 4 × 256 = 1 KiB |
| `MAX_SOCKETS` | 4 → 16 | `src/net.rs` | one socket per service domain |
| `MAX_SCHED_ENTITIES` | 8 → 64 | `src/sched.rs` | the sharpest old mismatch: 64 domains existed, only 8 could ever be runnable |
| `MAX_INODES` | 64 → 128 | `src/vfs.rs` | boot tree + a shell session's creations + scratch files |
| `NAME_MAX` | 28 → 64 | `src/vfs.rs` | real file names fit |
| `MAX_FDS` | 16 → 32 | `src/fd.rs` | stdio + a pipe pair + files + dup'd handles; the ABI ceiling is the u8 fd (256), pinned by a const assert |
| `MAX_EXEC_ENTRIES` | 16 → 32 | `src/proc.rs` | one declared surface per registry image plus third-party binaries |
| `TELEMETRY_CAPACITY` | 16 → 64 | `src/response.rs` | a boot's worth of monitor events before the drop counter engages |
| `MAX_READ` / `MAX_WRITE` | 256 → 4096 | kernel `sysabi.rs` / `syscall.rs` | one page per chunk; the copy buffer rides the 32 KiB guarded syscall stack |

## The boot-stack decision

`Kernel<4096>` is a kmain stack local, and the boot stack is the F15
guard-page-cliff in `linker.ld`. Round J had sized it 512 KiB against a
216 KiB kernel state and ~40 KiB of measured deep driver-stack chains.
Growing the state to 455 KiB inside the same 512 KiB would have left
~17 KiB — under the chain depth. The stack therefore grew 512 KiB →
1 MiB. 768 KiB was tried first and FAILED on the pc lane: the no-DMAR
arm's driver-stack chain (pci_step's bridge walk after ecam_window's
scratch buffers) exhausts what remains below the 455 KiB Kernel —
an unhandled #PF mid-`pci_step`, caught by lane probes. At 1 MiB the
lane is green end to end. The linker's 2 MiB single-page ASSERT still
bounds image + bss + stack (image ~896 KiB + 1 MiB stack + guard ≈
1.88 MiB, ~121 KiB of page headroom left for code growth — the next
raise should move the Kernel to .bss, see the note below).

Host tests build `Kernel` on test-thread stacks; the deep-park tests
measurably overflowed the default at 455 KiB, so `RUST_MIN_STACK=16777216`
is pinned in the CI workflow env and in the local gate runner
(`scripts/gates.sh`, the `test` gate).

## The proof

- **Host:** `tests/capacity_accounting.rs` asserts the state budget;
  the fill/refuse/drain/reuse and exhaustion tests in the core
  (`proc_model.rs`, `ipc.rs`, `net.rs`, `sched.rs`, `response.rs`,
  `proc.rs`) pin every raised edge — they reference the constants, not
  literals, so they re-pin automatically on the next raise.
- **Boot:** kmain step 8b prints
  `[CAP] limits: ... state=455KiB` (the measured number, at boot),
  fills the domain table to 64 (refusal: `TooManyDomains`), the socket
  table to 16 (`TableFull`), the endpoint table to 32 (`TableFull`,
  across three owners so the endpoint layer — not an owner's cap table —
  is the layer that refuses), drains everything, and reuses the tables.
  The verdict line all seven lanes grep:
  `[CAP] selftest: fill/refuse/drain/reuse ok (all layers honest)`.

### A bug the raise found

With both tables at 8 slots, a full owner capability table was
unreachable through `ipc_endpoint_create`. At 32/32 the supervisor
test hit it — and the refusal had been *mislabeled* `IpcError::TableFull`
(the endpoint table) when the owner's capability table was the layer
that refused. K20 split the variant (`IpcError::OwnerCapFull`, errno
`-ENOMEM`), kept the rollback (no slot leaks), and the supervisor test
now pins both layers separately. This is the pattern the mission asked
for: raises make hidden dishonesty reachable, and the honest-refusal
invariant is what the tests actually protect.

## Deliberately NOT raised (and why)

- `FILE_DATA_MAX = 1024` — inline in every inode, so it multiplies
  `MAX_INODES`; a 4 KiB window measurably overflowed the deep-park host
  tests' stacks at 64 inodes. Real file data goes through the ext2/FAT32
  paths; this is the boot-time ramfs.
- `IPC_QUEUE_DEPTH = 4` — per-endpoint message queue depth; EAGAIN-style
  bounded back-pressure is the design, not a bug.
- `SYSCALL_COUNT = 64` — the syscall mask is a `u64`; widening it is an
  ABI change, not a capacity change.
- `MAX_VTD_DOMAINS = 16` — VT-d hardware domain contexts; the boot
  claims ~8 devices and a second driver domain (P0-4) fits.
- `TABLE_BUDGET = 195` in `vtd.rs` — the worst-case second-level page
  table count for 16 domains (ADR-0018); raising `MAX_VTD_DOMAINS`
  raises it mechanically.
- `MAX_PARTS = 4` — GPT/MBR partition entries the probe walks.
- Kernel `MAX_PATH = 128` — bounds the copy-in; components are bounded
  by `NAME_MAX` (now 64).
- `MAX_SESSION_FRAMES = 16`, `DmaQuotas` (`max_regions: 16`,
  `max_bytes: 64 KiB`) — per-session driver budgets; the largest current
  session (virtio-net) maps 8 regions / 32 KiB.
- Frame pool: 4096 frames (16 MiB) — untouched; every user page,
  page-table page and DMA region comes from it.

The next raise that matters is `FILE_DATA_MAX` (or moving inode data
off the inline window), and it should come with the Kernel-to-.bss
move that takes the state off the boot stack entirely (it needs one
`unsafe` block and an ADR — the unsafe-count gate tracks it).
