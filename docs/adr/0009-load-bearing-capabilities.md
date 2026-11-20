# ADR-0009: Capabilities become load-bearing

- Status: Accepted
- Date: 2026-11-20 (second deep review, Phase F / F18)
- Deciders: kernel maintainers
- Related: ADR-0004 (capability endpoint IPC), ADR-0007 §2 (live gate)

## Context

`Domain.caps` existed since M0 but no syscall ever consulted it —
ARCHITECTURE.md claimed capability enforcement that was not
implemented. The review (F18) requires capabilities to gate the
resource-touching syscalls, with Unix DAC remaining as a second layer.

## Decision

1. **`Resource` is the full resource model**: `FsNode(InodeRef)`,
   `Device(u32)`, `Domain(u32)`, `Endpoint(u32)` (IPC endpoints —
   reserved for the IPC slices, not yet enforced; explicit TODO below).
2. **Creation mints the initial capabilities from the profile's
   `base_rights`** (`Kernel::create_domain_with`):
   - `FsNode(ROOT_REF)` with `base_rights` — the root of the VFS tree.
     A capability on a directory covers operations whose *parent
     directory* is that directory or any descendant of it
     (`Vfs::is_within` walks the parent chain; bounded, cycle-free by
     construction). Deeper scoping (e.g. a chroot minting a capability
     on the new root) is future work.
   - `Device(0)` with `base_rights` — the (single, brokered) NIC.
   - `Domain(id)` with `Rights::WRITE` — the domain may signal *itself*
     (self-kill stays allowed with no special case: the minted
     capability passes the normal check).
   Nothing else is minted: cross-domain kills require a supervisor
   grant; endpoints wait for IPC.
3. **Enforcement order** (each failure is loud and counted):
   1. the **mask gate** (existing),
   2. the **capability gate** — `Open`/`Mkdir`/`Unlink` need an
      `FsNode` capability covering the path's parent directory with the
      requested right (READ to open for read, WRITE to open for
      write/create/unlink); `NetSend` needs `Device(0)` with WRITE;
      `Kill` needs `Domain(target)` with WRITE unless target == self.
      Every failure increments the live domain's escalation signal
      through the same recording path as the `cap_*` wrappers.
   3. the **Unix DAC layer** (unchanged),
   4. for `Kill`, existence is revealed only after 1-3 pass — the F14
      enumeration protection is preserved (an unauthorized sender gets
      PermissionDenied for existing and missing targets alike; note
      this *supersedes* F14's "uid 0 gets the honest UnknownDomain":
      root without a Domain capability is unauthorized too, and is told
      so identically for existing and missing ids).
4. **A domain cannot mint capabilities**: the capability table is only
   writable through supervisor-facing APIs (`Kernel::cap_*`,
   `domain_mut`); no syscall path inserts, derives, or revokes. The
   table can only shrink through supervisor revocation.

## Consequences

- A domain with the right syscall mask but without the capability is
  denied and recorded (test), revocation takes effect on the next
  syscall (test), and derivation never exceeds the parent (the M0
  property, unchanged).
- The whole layer is host-tested (the lib owns it; the ring-3 executor
  surface only implements WRITE/EXIT today, so no kernel-side changes
  were needed).
- TODO (explicit, not implemented): `Endpoint` enforcement when IPC
  syscalls get executors; per-inode grants (today a capability on the
  root covers the whole tree — least privilege is delegated to profiles
  and future grant syscalls); a supervisor grant API for Domain
  capabilities beyond self.

## Slices

Landed in one slice: the full FsNode/Device/Domain set above (the lib
surface is small enough to land complete; no partial-doc risk).
