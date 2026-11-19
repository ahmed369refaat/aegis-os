# Contributing to AegisOS

Thank you for helping build a kernel whose security claims are only as
strong as their proofs. This document is the contract every PR signs up
to. The short version: **small PRs, tests that prove the invariant, CI
boots it, docs explain it.**

## Workflow

1. Pick work from the current stage in [`docs/ROADMAP.md`](docs/ROADMAP.md)
   (or its PR plan, e.g. [`docs/STAGE1-PR-PLAN.md`](docs/STAGE1-PR-PLAN.md)).
   One stage at a time — PRs that reach into a future stage are deferred,
   not reviewed, unless the roadmap says otherwise.
2. Branch from `main`: `git checkout -b stage1/1.1-exceptions`.
3. Commit style: `area: summary` (e.g. `arch: exception machinery`),
   wrapped at ~72 chars, body explains *why* and names the tests added.
4. PRs ≤ 500 lines of diff (excluding generated blobs and docs). If your
   change is bigger, split it — the PR plans already do.

## The PR checklist (CI enforces most of this mechanically)

- [ ] **Tests**: every new logic module has host tests; ≥ 80% line
      coverage on host-testable code (`cargo llvm-cov`). Boot/arch paths
      are covered by QEMU integration tests with marker greps — if your
      coverage is in that bucket, say so in the PR.
- [ ] **QEMU test**: `./boot.sh --verify` passes; if your PR adds a
      behavior, it adds a marker the script (or CI) asserts.
- [ ] **No isolation/W^X regressions**: any change that could widen a
      live domain's mask, bypass the gate order, or map user memory
      executable is rejected by review even if tests pass — and there
      must be a test proving it *cannot*.
- [ ] **Unsafe policy**: `unsafe` only inside the allowlisted modules
      (`boot/`, `hw.rs`, `memops.rs`, growing per ADR), each item with a
      `// SAFETY:` comment. The total unsafe count must not exceed
      `scripts/unsafe-count.txt`; raising it requires an ADR reference
      in the PR (CI fails otherwise). `cargo-geiger` can be run locally
      as a cross-check; the zero-dependency CI job uses our own
      `scripts/check_unsafe.sh`.
- [ ] **Docs**: new component → `docs/<component>.md` with design,
      invariants, and a threat-model section.
- [ ] **ADR**: architectural decision (layouts, ABIs, protocols,
      security mechanisms) → an ADR in `docs/adr/` *before* the code.
- [ ] **ABI**: anything touching syscall numbers/structures/errno →
      bump `docs/ABI-VERSION.md`.
- [ ] **Benchmarks**: hot-path changes (gate, IPC fast path, page
      tables, scheduler) run the relevant `bench/` harness; > 5%
      regression fails CI unless the PR justifies and re-baselines it
      (with an ADR for the trade-off).

## Development setup

```bash
./boot.sh                 # build + boot in QEMU (needs qemu-system-x86)
./boot.sh --verify        # CI-grade proof run
cargo test                # policy-core tests
cargo test -p aegis-kernel  # kernel host tests (boot logic)
scripts/check_unsafe.sh   # the unsafe allowlist + count gate
```

Rust stable, no external dependencies in shipped artifacts — ever. If a
PR adds a `[dependencies]` entry that is not a workspace member, it is
rejected; developer tools that are not shipped (formatters, coverage
runners) are fine locally but do not belong in CI jobs.

## Code style

- The policy core (`src/`) stays `#![forbid(unsafe_code)]` and fully
  host-testable. The kernel is `#![deny(unsafe_code)]` with the
  documented allowlist. Match the surrounding style; comment density
  follows the existing files (dense where invariants live).
- Naming: kernel arch code `snake_case` modules under
  `kernel/src/arch/<arch>/`; arch-agnostic code never imports arch
  modules directly — it goes through `arch::` traits.
- Every invariant comment is testable: if you write "this can never X",
  there is a test that tries X.

## Reporting security issues

Open a GitHub issue with the `security` label; do not attach exploits
publicly before a fix lands. Every fix ships with a regression test and
a threat-model delta in the relevant `docs/<component>.md`.

## License

MIT (see [LICENSE](LICENSE)). Contributions land under the same license.
