# Incident: ELF core dump committed with the build machine's environment

- Date: 2026-11-20
- Severity: high (credential exposure in public history)
- Status: file untracked and guarded (this commit); **history purge and token
  rotation are HUMAN steps — see the runbook below. Not done by the agent.**

## What happened

`kernel-x86_64/core` — an 8,167,424-byte ELF64 core dump (`e_type = 4`,
`ET_CORE`) — was committed to this repository (commits `b582c29`, `d09af9c`,
`76237cf`; copies are also reachable through the `refs/original/*` refs left
behind by an earlier history rewrite, commits `d9c7adf`, `c898b2c`,
`59805a7`). A Linux core dump embeds the crashing process's memory **including
its environment block**. The environment of that process contained a
credential variable, `ZCODE_OFFICIAL_ENDPOINT_TOKEN` (name documented; the
value is deliberately not reproduced anywhere in this repository). Anyone who
has a clone from before the purge can recover the value with:

```
strings kernel-x86_64/core | grep -A2 ZCODE
```

Treat the **entire environment** of the crashing process as exposed, not just
the one named variable: everything exported in that shell (other tokens,
proxy credentials, anything) is in the blob.

## What crashed (measured, not guessed)

- Crashing image:
  `target/debug/build/aegis-kernel/db1164b93cb11f8b/out/aegis_kernel-db1164b93cb11f8b`
  — the **host** build of `kernel-x86_64` (a PIE ELF of `kernel-x86_64/src/main.rs`,
  per its `.d` file).
- Signal: **6 (SIGABRT)**, `si_code = -6` (`SI_TKILL` — a userspace
  `raise()`/abort, consistent with a Rust panic-abort).
- Interpretation: the kernel ELF built for the host was executed directly on
  the Linux dev machine (not inside QEMU). A freestanding, higher-half kernel
  cannot run as a host process; it aborted immediately. The default
  `core_pattern` wrote the 8 MiB core into the working tree
  (`kernel-x86_64/` was that shell's CWD), and it was later committed by
  accident together with real work.

Prevention on the workflow side: never execute the `aegis_kernel-*` host
artifacts directly; the only supported way to run the kernel is
`./boot.sh` (QEMU). The guard below makes a recurrence CI-fatal.

## What this repository already does about it (automated part)

1. `kernel-x86_64/core` is untracked (`git rm`) and deleted from the worktree.
2. `.gitignore` covers `core`, `core.*`, `*.core`, `vgcore.*`.
3. `scripts/check-no-binaries.sh` (wired into CI, supply-chain job, with a
   `--self-test` that builds its fixtures at test time and never commits
   them) fails the build on: any tracked ELF core (`e_type == 4`), any
   tracked file over 1 MiB outside an explicit allowlist
   (`kernel-x86_64/blob/*.bin`), and any tracked text file matching
   credential patterns (token/secret/api-key assignments, GitHub and AWS key
   prefixes, private-key PEM headers).

These steps stop the file from being tracked again. They do **not** remove
it from history — git keeps every version of every tracked file reachable
from any ref.

## HUMAN runbook (in this order; none of it is automated)

1. **Rotate the credential now.** Invalidate `ZCODE_OFFICIAL_ENDPOINT_TOKEN`
   at the provider that issued it and issue a fresh one. This is the only
   real fix: the blob has been pushed, so forks, clones and any cache
   (GitHub's object storage, forks' refs, CI logs) may retain it forever.
   Rotation first, history cosmetics second.
2. **Purge the file from all history.** On a fresh clone:
   ```
   git filter-repo --path kernel-x86_64/core --invert-paths
   ```
   Then make sure the stale `refs/original/*` refs from the earlier rewrite
   are gone too (filter-repo normally clears them, verify with
   `git for-each-ref refs/original`), expire reflogs
   (`git reflog expire --expire=now --all`) and run `git gc --prune=now`
   before pushing.
3. **Force-push all refs and tags.** `git push --force --all` and
   `git push --force --tags`. This rewrites public history — coordinate with
   collaborators first. (This step is deliberately left to a human; no
   automation in this repository ever rewrites history or force-pushes.)
4. **Ask forks and clones to re-clone.** Old clones keep the blob in their
   object stores even after the upstream is purged.
5. **Disable core dumps in the dev shell** so this cannot recur:
   `ulimit -c 0` (or `limit coredumpsize 0`), or system-wide with
   systemd-coredump set to `storage=none`. The CI guard catches a
   recurrence at push time even if the shell setting is forgotten.
6. Optionally, check what else that environment block contained before
   rotating (step 1 should not wait for this).

## Evidence trail

- `readelf -n kernel-x86_64/core`: `NT_PRPSINFO` names the crashing image;
  `NT_SIGINFO` shows signo 6, code −6; `NT_FILE` maps only the kernel PIE,
  libc and libgcc — no QEMU involved.
- `git log --oneline --all -- kernel-x86_64/core`: the commits listed above.
- `scripts/check-no-binaries.sh --self-test`: proves the guard detects every
  case (ELF core, oversize file, each credential pattern) with no false
  positives on benign fixtures.
