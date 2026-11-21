# Architecture Decision Records

Every decision that shapes the kernel's architecture gets an ADR: one
file, one decision, written **before** the code lands. If a PR changes
an architectural decision without a matching ADR (new or superseding),
it does not merge.

## Process

1. Copy `TEMPLATE.md` to `NNNN-short-title.md` (NNNN = next free number).
2. Status starts at `Proposed`; it becomes `Accepted` when the
   implementing PR(s) merge, or `Rejected`/`Superseded by NNNN` later.
3. ADRs are never edited after acceptance except to add a superseding
   link — corrections happen in a new ADR.
4. PRs that grow the unsafe allowlist or raise the unsafe-count baseline
   **must** reference the ADR that justifies it.

## Index

| ADR | Title | Status |
|---|---|---|
| [0001](0001-two-stage-elf32-boot.md) | Two-stage ELF32 boot stub | Accepted (retroactive, M1) |
| [0002](0002-higher-half-kernel-layout.md) | Higher-half kernel + direct map | Accepted (PR-1.2) |
| [0003](0003-linux-compatible-syscall-abi.md) | Linux-compatible syscall ABI | Proposed (Stage 5) |
| [0004](0004-capability-endpoint-ipc.md) | Capability-endpoint IPC | Accepted (async half landed, M2-W1) |
| [0005](0005-exception-machinery.md) | Exception machinery + arch/ allowlist | Accepted (PR-1.1) |
| [0006](0006-kernel-image-wx-ist-stacks.md) | Kernel image W^X + IST stacks in .bss | Accepted (F15/F16) |
| [0007](0007-user-copy-faults-and-live-monitor.md) | User-copy faults + live monitor feeds | Accepted (N1/N2) |
| [0008](0008-smep-smap.md) | SMEP/SMAP | Accepted (N4) |
| [0009](0009-load-bearing-capabilities.md) | Load-bearing capabilities on resource syscalls | Accepted (F/F18) |
| [0010](0010-ring3-reliability-four-root-causes.md) | Ring-3 reliability: four root causes | Accepted (M2-W2) |
| [0011](0011-multi-architecture-hal-bsp.md) | Multi-architecture HAL/BSP strategy | Accepted (design; restructure = Phase 2 of GAP-ANALYSIS-v2) |
| [0012](0012-timer-preemption.md) | Timer preemption: LAPIC tick, parked runs, frame-rewrite switch | Accepted (machinery landed; boot demo feature-gated pending open issues) |
| [0013](0013-iommu-vtd-dma-isolation.md) | IOMMU/VT-d: kernel-brokered DMA isolation for driver domains | Accepted (Phases 0–2 + enforcement live on the q35 lane; ADR-0014/0015 hardening) |
| [0014](0014-context-entry-tt-multilevel.md) | Context-entry TT=0b10: second-level translation is load-bearing | Accepted (the pass-through bug fixed in 3f7ca26) |
| [0015](0015-map-run-atomicity-poison-quarantine.md) | map_run atomicity, poison quarantine, domain-scoped cookies | Accepted (F1–F3 in d7a1ca9; the one-close() unification is ADR-0016/F10) |
| [0016](0016-driver-stack-modules-mmio-bus-driver-session.md) | Driver-stack modules, MmioBus windows, one-close() DriverSession | Accepted (review round 4, Phase 4) |
| [0017](0017-ring3-driver-domains.md) | Ring-3 driver domains: drivers as monitored, brokered clients | Accepted (first slice — IpcMmio + device core — host-proven; ring-3 transport next) |
| [0018](0018-one-iommu-domain-per-device.md) | One IOMMU domain per device: kernel-allocated ids, scoped sessions, sized table budget | Accepted (review round 5, Phase A) |
