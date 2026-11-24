# ADR-0032: Attenuation is a checked relation, not a convention — profile requests, exec policy, and shared-frame accounting

- **Status:** Accepted (section A implemented this round; sections B and C land with their items in the same round)
- **Stage:** M3 security hardening (post-shell/exec/ext2 review, round A2/A3/A4)
- **Date:** 2026-11-24

## Context

The round-A review proved three independent ways a child could be
WEAKER-MONITORED or more privileged than its parent:

1. **Spawn validated two of seven profile axes.** `spawn_process`
   checked only `syscalls ⊆ parent live mask` and `quota <= parent` —
   reproduced live: a parent with `max_children = 2` ACCEPTED a request
   with `sensitivity = 0` (monitor nearly blind), `degraded_syscalls =
   syscalls` (the Tighten tier is a no-op), and `max_children = 1000`
   (a 500x fan-out). The other request fields were copied into the
   child verbatim.
2. **Exec downgraded monitoring and keyed policy by a path string**
   (section B, ITEM 3): `exec_replace` assigned `monitor_enforce`
   unconditionally, `ExecPolicyTable::declared_for` was keyed by the
   path STRING (aliases missed the declared policy), and unlisted
   images were born AuditOnly.
3. **The shared-frame table capped fork at 64 entries system-wide**
   (section C, ITEM 4): a linear `[Option; 64]` acquired for every
   present user page, so any process with more than ~64 distinct pages
   could not fork; exhaustion was reported with the wrong error
   variant.

The invariant all three break: **attenuation-only** — a child's mask,
capabilities, quota, monitor strictness and device rights are always at
least as restricted as its parent's, at every spawn/fork/exec.

## Decision (section A — ITEM 2): `DomainProfile::is_attenuation_of`

A pure, host-tested relation on `DomainProfile`, used at every point a
REQUESTED profile becomes a live domain (spawn today; exec's declared
policy in section B). It takes the parent's CLASS profile plus the
parent's LIVE state (the possibly-tightened mask and quota — the
child must fit under what the parent has NOW, not what its class was
born with) and returns `Result<(), ProfileViolation>` with a typed
reason per axis:

- `syscalls ⊆` the parent's LIVE mask (not merely the class profile);
- `quota_pages <=` the parent's LIVE quota;
- `sensitivity >=` the parent's (monitor strictness never drops);
- `degraded_syscalls` a PROPER subset of `syscalls` (Tighten must be
  able to actually tighten) that always contains the exit call (a
  tightened domain can always leave);
- `max_children <` the parent's (strict — fan-out strictly decays down
  the tree; `==` is refused);
- `base_rights ⊆` the parent's base rights.

**The implementation destructures `DomainProfile` exhaustively — no
`..`** — so adding a field breaks the build until someone classifies
it as authority, limit, or monitor parameter and extends the relation.
`name` is destructured and explicitly classified as pure metadata (no
authority — a label).

**Structural finding (recorded for the maintainer):** the round brief
lists "monitor enforce mode monotone" among the profile checks, but
`monitor_enforce` is DOMAIN state (`domain.rs`), not `DomainProfile`
state — the exhaustive destructure cannot see it. The monotonicity
therefore lives at its single mutation sites: spawn INHERITS the
parent's mode (monotone by construction, no choice is made), and
exec's assignment becomes a ratchet in section B. Fork copies the
profile and mode verbatim (`Domain::forked`) and never passes through
the request path — unchanged, as the brief requires.

**Every violation is recorded as an escalation attempt on the parent** — the
existing `record_escalation_attempt` pattern, extended to all axes.

### Tests (red first)

One host test per axis (each constructs an otherwise-legal request and
flips exactly one field), the prompt's reproduced case verbatim
(`max_children=2` parent, `sensitivity=0` + `degraded=syscalls` +
`max_children=1000` request → refused), and a seeded property test
over random profile pairs: a request that PASSES is never weaker on
any axis (mask subset, quota ≤, sensitivity ≥, fan-out <, rights
subset, degraded proper-subset-with-exit). The existing lifecycle
tests that legitimately set `degraded = syscalls` and large
`max_children` are updated to legal values (named in the commit).

## Decision (section B — ITEM 3): exec ratchets, policy by IMAGE identity

- **The monitor ratchet** (`exec_replace`): `(Some(true), _) =>
  Some(true)` — once Enforce, always; `(old, None) => old` — a None
  parameter is INHERIT (exactly what the unlisted-image arm passes:
  the caller's state rides across untouched); `(_, declared) =>
  declared` — a Some(_) parameter is a real declared decision for
  THIS image and lands (it can never lower an Enforce — the first
  arm). This kills the round-A downgrade (an Enforce domain exec'ing
  an unlisted image became AuditOnly) while keeping a declared
  AuditOnly reachable — Some(false) must be a meaningful state, or
  "AuditOnly" could never mean anything.
- **The policy table is keyed by IMAGE IDENTITY** — a 64-bit FNV-1a
  content hash of the registry image bytes (`proc::image_id`), never
  a path string. Aliases of the same bytes resolve to one entry by
  construction; different bytes never inherit a policy they did not
  declare. FNV-1a is NOT cryptographic — recorded as a deliberate,
  environment-honest choice: the registry is two kernel-embedded
  images, the table never widens anything (masks only intersect), and
  a collision would confuse two KERNEL-CHOSEN images, not hand user
  input a privilege.
- **`canonicalize_path`** (pure, bounded): collapse `//`, resolve `.`
  and `..` (saturating at the root, POSIX-style — never escaping
  upward), drop trailing slashes, refuse non-absolute input and
  output overflow. `sys_exec` canonicalizes BEFORE the registry
  lookup — `/bin/x`, `//bin/x`, `/bin/./x`, `/bin/../bin/x` are one
  entry, so no spelling can dodge a declared policy.
- **Unlisted images**: no table entry — the caller arm passes the
  app-default surface (intersected with the live mask inside
  `exec_replace`, which never widens) and None (inherit the caller's
  monitor mode). The old code returned Some(false) for unlisted
  paths — the silent downgrade.
- **Persistence**: violation counters, monitor stats, tightened state
  and the quarantine flag ride across exec (nothing in the path
  clears them; the test pins it). Caught signal handlers still reset
  (POSIX; the new image installs its own) and the address space still
  clears — both unchanged.
- `exec_replace`'s mask intersection and the kernel-side atomic image
  replacement are untouched.

### Tests (red first)

`exec_never_downgrades_the_monitor_mode` (red on the old
unconditional assignment — `left: Some(false), right: Some(true)`,
the exact round-A shape), `exec_stats_and_violations_survive_the_
boundary`, `a_policy_declared_for_one_image_never_applies_to_another`
(the mismatch case), `random_exec_chains_never_loosen_mode_or_mask`
(500 seeded execs: the mode never turns off, the mask never gains a
bit), `path_aliases_canonicalize_to_one_entry` and
`image_identity_is_content_addressed` (pure), and the kernel-side
`aliases_canonicalize_to_the_same_image_and_identity` (the embedded
registry bytes). Boot: `--verify` and the shell lane PASS with the
identity-keyed declaration live (PID 1's /bin/sh exec and the
linux-abi execve round-trip both cross the new boundary).

## Decision (section C — ITEM 4): per-frame reference counts

(Section C lands with its item in this round: the linear 64-entry
table replaced by per-frame reference counts indexed by pool frame
number — O(1), overflow-checked; `cow_decision`/`CowDecision` keep
their meaning; a new `MapError::ShareLimit` replaces the wrong
`KernelHalf` variant; the ADR-0027 page-grant bound stays separate and
configurable.)

## Consequences

- A spawn request is now legal only if EVERY authority axis attenuates.
  The cost: test profiles (and future callers) must be built
  honestly — the updated tests show the pattern (a child of a
  max_children-8 service may ask for at most 7, with a degraded tier
  strictly inside its surface).
- The typed `ProfileViolation` makes audit logs and future telemetry
  name the axis that was attacked, not just "escalation".
- What we do NOT do: no change to `fork_process` (verbatim copy, the
  brief's requirement); no new syscalls; no rename of the existing
  `ProcError::ProfileEscalation` transport (the typed reason is the
  pure relation's return; widening the error enum would ripple the
  core API — recorded as a decision needing maintainer review).
