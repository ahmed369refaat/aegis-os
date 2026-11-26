# THREAT MODEL — the AegisOS package manager (`pkg/`)

Each threat from the design brief, the mitigation, and where in the
code it lives. Every claim below is pinned by a test in
`src/tests/mod.rs`.

## 1. Supply-chain compromise (malicious repo, malicious maintainer key)

**Model.** An attacker controls repository content, or steals a
repository's signing key, or tries to inject their own key.

**Mitigation.** A chain of custody with no in-band key updates
(`src/repository.rs`):

- Root anchors (Ed25519 public keys) live in `/pkg/trust`,
  admin-provisioned, **never fetched** — nothing an attacker
  transmits can add an anchor.
- Each repository's verification key lives in
  `/pkg/repos/<slug>.repo`, written only by an explicit,
  out-of-band `pkg repo add`. A key shipped *inside* repository
  metadata is structurally unable to replace it: the index parser
  never reads keys from the index.
- Indexes (AKI1) carry (a) a repo signature over the whole body and
  (b) optionally a root signature over body + repo signature. A
  chain-anchored repo must verify under an anchor
  (`load_repos` tries each anchor; `parse_index` enforces both
  layers). An index without a root signature is accepted only for
  admin-pinned repos — deliberate trust-on-first-use, reported
  loudly at `repo add` time.
- Every package's SHA-256 is pinned by the signed index, and the
  candidate universe is built only from packages whose AKP1
  signature verifies under the repo key (`fill_universe` in
  `src/cli.rs`): an unsigned or mis-signed package is not merely
  refused at install — it cannot even be *resolved*.
- The package signature covers the canonical manifest bytes
  (`PackageHeader::verify_signature`, `src/package.rs`), and the
  manifest's per-file hashes bind every payload byte.

**Residual risk.** A compromised *pinned* repo key can sign
malicious-but-well-formed content that the manager will install;
the installed bytes are still exactly the signed bytes, and the
root-anchored mode exists precisely to remove this residual (the
attacker must then also compromise a root anchor, which never
leaves the machine).

**Tests.** `tampered_signature_rejected`, `tampered_index_rejected`,
`unknown_repo_rejected`.

## 2. Signature replay

**Model.** Re-present an old, validly signed artifact or index to
roll the system back.

**Mitigation.** Signatures bind content, so replay defense is
metadata-layered (`src/database.rs`, `RepoEpochs`):

- Per-repo monotonic index epochs: a *lower* epoch is refused
  (`ErrorKind::Replay`), and the *same* epoch with *different*
  bytes is refused (mutation/rollback at equal epoch).
- Version ordering + the downgrade block (threat 3) stop an old
  signed package from displacing a newer installed one.

**Test.** `repo_epoch_replay_defense`, `downgrade_blocked_and_forced`
(the repo regression scenario).

## 3. Downgrade attack

**Model.** Install `evil@1.0.0` over `libssl@2.0.1`.

**Mitigation.** Enforced twice: the solver skips candidates that
are not newer than the installed version unless
`--force-downgrade` was passed (`Solver::resolve_into`), and the
transaction re-checks at the enforcement point
(`Transaction::install_package`) so even a direct install path
cannot bypass it. The flag is a root decision (the `/pkg` tree's
Unix permissions gate who can run mutating commands at all).

**Test.** `downgrade_blocked_and_forced` (blocked, then forced).

## 4. Dependency confusion / typosquatting

**Mitigation.** Names are mandatory two-part namespaces
(`repo/pkg`, `manifest::validate_name`): bare names cannot exist,
and a dependency on `repo/pkg` resolves **only** in that repo's
entries — a same-named package in another repository never
satisfies it. Both name parts are ≥2 chars of
`a-z 0-9 - . _`, must start/end alphanumeric: no case tricks, no
Unicode lookalikes, no 1-character near-misses; the CLI always
displays the full namespaced name, so a typosquat must fake the
namespace too.

**Tests.** `hostile_fields_refused` (name charset/shape),
`solver_cycle_detected` (namespacing in the solver universe).

## 5. Malicious package contents (traversal, symlinks, hardlinks)

**Mitigation.**

- **Path traversal** (`../../../etc/passwd`): `Path::from_bytes`
  (`src/lib.rs`) rejects non-absolute, empty, `.`/`..`, NUL, and
  over-long components; `Manifest::validate` runs the full
  allow-list check (files may only land under `/bin /lib /etc
  /usr /share`, never `/pkg`, `/dev`, `/kernel`). Pinned twice —
  at parse and at the transaction's parent walk.
- **Symlinks**: extraction only ever writes into
  freshly-created staging files (`O_CREAT|O_EXCL`) inside the
  manager's own staging root; before every commit rename, each
  destination parent is `stat`-verified as a real directory — a
  symlink on the walk aborts the transaction
  (`Transaction::move_into_place`). Packages cannot pre-plant
  links under `/pkg` (the allow-list forbids it), so the manager's
  own tree is untouchable.
- **Hardlinks to sensitive files**: a hardlink at a destination is
  simply *replaced* by the rename (rename never follows); a
  hardlink planted as a destination *parent* fails the
  non-directory check.
- **TOCTOU on extraction**: after writing a staged file, it is
  re-opened through a *fresh* fd and re-hashed before any rename
  (`reverify_staged`) — a racing writer between write and verify
  is detected and the whole transaction aborts.

**Tests.** `hostile_paths_refused`, `symlink_parent_escape_refused`.

## 6. Partial install / power loss

**Mitigation.** The transaction protocol (`src/transaction.rs`):
lock → recovery → stage → journal (WAL, CRC-framed, fsynced) →
renames → Commit marker → cleanup. Destinations are only ever
touched by renames of fully-staged, doubly-verified files, in
journaled order. Crash windows:

- before renames: nothing moved, staging discarded;
- during renames: recovery reverses every applied op (moves back,
  created dirs unlinked, removals restored from journaled backups);
- after Commit: recovery only cleans up.

Stale locks are resolved by the same replay (the journal tells
whether the holder crashed mid-commit or before any state change).

**Test.** `crash_during_commit_recovers` (crash after the first
rename; the next command rolls back; a fresh install succeeds).

## 7. Concurrent invocations

**Mitigation.** `/pkg/lock` is created `O_CREAT|O_EXCL` — atomic
against any second process; the loser fails fast with
`ErrorKind::Locked`. Power loss while holding leaves a stale lock
that recovery removes (safe because recovery is itself
journal-driven).

**Test.** `concurrent_invocation_lockout`.

## 8. Disk-full during install

**Mitigation.** All payload writes flow through the extraction
sink; a `NoSpace` error propagates immediately, aborts the
transaction, and rolls back — a half-written staging file never
reaches a destination. Even an in-commit rename failure reverses
the applied prefix (`Transaction::commit`).

**Test.** `disk_full_rolls_back` (quota-exhausted install leaves
zero destination files; the retry succeeds).

## 9. Malicious manifest (huge fields, integer overflow, deep nesting)

**Mitigation.** Every manifest field is length-prefixed with
`u8`/`u16` widths and taken from *remaining input* — a huge claim
cannot allocate or copy out of bounds; the total is capped at
`MAX_MANIFEST`. File sizes are checked against the policy cap and
never used as indices (extraction streams). Dependencies are a
flat list (nesting is impossible); the solver caps recursion
(`MAX_SOLVER_DEPTH`) with cycle detection, and caps total steps
(`MAX_SOLVER_STEPS`) against adversarial combinatorics. All
arithmetic on untrusted values is `checked_*`/`saturating_*`.

**Tests.** `huge_length_claims_refused`, `hostile_fields_refused`,
`solver_cycle_detected`.

## 10. Zip-bomb-style payloads

**Mitigation.** Two independent guards in the extraction sink
(`HashingSink`, `src/package.rs`): the emitted size must equal the
*signed* declared size exactly, and the running total may never
exceed `100 × compressed-consumed + 4096`. Per-block literal/match
lengths are additionally capped at the 4 KiB block size, offsets
must reference real history within the 64 KiB window, and the
streaming ring decoder uses fixed memory regardless of file size.

**Test.** `decompression_bomb_refused` (20-byte blocks expanding
to 4 KiB windows trip the ratio cap mid-decode).

## 11. Symlink races during package DB writes

**Mitigation.** The DB tree is created by the manager; every
record/state write is staged then renamed with the same
parent-walk refusal as file installs; package manifests cannot
write under `/pkg` at all, so no package can pre-plant a symlink
or hardlink inside the manager's state. Recovery re-creates
missing parents during rollback rather than following anything.

**Test.** the DB round-trips inside every lifecycle test;
`symlink_parent_escape_refused` pins the walk refusal.

## 12. Malicious install scripts

**Mitigation.** File-only packages *by design*: the manifest
format has no script field, manifests carrying hook-shaped paths
are refused (`ScriptRefused`), and no code runs at install time
beyond the manager itself. The "sandboxed scripts" branch of the
brief is deliberately not taken — the attack surface it creates
(script interpreter domain, wall-clock/memory limits, script
content review) is avoided entirely.

**Test.** `hostile_fields_refused` (hook-path refusal path).

## Cross-cutting properties

- **`no_std`, `no_alloc`, zero dependencies**: the entire crypto
  and parsing stack is inline — the supply chain the manager
  defends is not extended by its own build. Ed25519 is pinned by
  RFC 8032 §7.1 vector 1 plus randomized consistency suites;
  SHA-256/512 by FIPS vectors.
- **No panics in library code**: every fallible path returns
  `Result`; the only `unwrap`s live in tests.
- **Constant-time comparisons** for every digest/signature
  equality (`crypto::ct_eq`).
- **No global mutable state**: no `static mut`; concurrency is
  handled by the filesystem lock, not threads.
