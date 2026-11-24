//! ADR round A6 (ITEM 8) — the syscall STORM fuzzer: a seeded,
//! deterministic 240k-op random walk over `Kernel::syscall` with
//! hostile operands (wraparound lens, traversal paths, invalid fds
//! and signals, W+X mmap attempts) against live domains of three
//! profile classes.
//!
//! The reviewer's bar (round brief): ZERO panics and ZERO
//! mask-widening across the whole storm. The invariant is checked
//! live: every surviving domain's mask stays a subset of its
//! baseline (the monitor may Tighten or Quarantine — bits only ever
//! leave), and escalation counters never go backwards. Scale with
//!
//! `AEGIS_FUZZ_OPS` (CI runs the default 240_000).

use aegis_os::prelude::*;
use aegis_os::profile::{app_profile, parser_profile, service_profile, DomainProfile};
use aegis_os::sys::SysRequest;

/// The seeded xorshift the property tests already use (proc_model,
/// fork_reclaim) — deterministic, no dependencies.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
}

/// The op count: 240k by default (the reviewer's bar), overridable
/// with `AEGIS_FUZZ_OPS` for a quick smoke run.
const OPS: usize = 240_000;

/// The operand pool — deliberately hostile, bounded (so the VFS node
/// count stays bounded across 240k creates): valid files, missing
/// files, traversal shapes, the chroot root, and a NAME_MAX-over path.
const PATHS: [&str; 10] = [
    "/home/notes.txt",
    "/home/storm.txt",
    "/etc/motd",
    "/no/such/file",
    "/",
    "..",
    "../../etc",
    "/home/./notes.txt",
    "/home/../home/storm.txt",
    "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/b",
];

/// The four storm domains (ids 1..=4), one per profile class plus an
/// attenuated child: (id, profile).
fn storm_domains() -> [(u32, DomainProfile); 4] {
    let mut child = app_profile();
    // A legal child of the service surface: subset mask, exit-keeping
    // tighten tier, smaller quota, higher sensitivity, lower fan-out.
    child.syscalls = SyscallMask::from_bits(
        1u64 << SYS_READ
            | 1u64 << SYS_WRITE
            | 1u64 << SYS_OPEN
            | 1u64 << SYS_CLOSE
            | 1u64 << SYS_EXIT,
    );
    child.degraded_syscalls = SyscallMask::from_bits(1u64 << SYS_EXIT);
    child.quota_pages = 32;
    child.sensitivity = 80;
    child.max_children = 2;
    [
        (1, service_profile()),
        (2, parser_profile()),
        (3, app_profile()),
        (4, child),
    ]
}

#[test]
fn the_syscall_storm_never_panics_and_never_widens_a_mask() {
    let ops: usize = match std::env::var("AEGIS_FUZZ_OPS") {
        Ok(v) => v.parse().unwrap_or(OPS),
        Err(_) => OPS,
    };
    assert!(ops >= 1_000, "the storm must be non-trivial");
    let mut k = Kernel::new();
    let domains = storm_domains();
    for (id, profile) in domains {
        k.create_domain_with(id, profile, 0, 0, 0).unwrap();
    }
    // The baseline: what each live domain's mask STARTS as (a killed
    // and re-created domain resets its baseline — the invariant is
    // "while it lives, bits only ever leave").
    let mut baseline: [Option<u64>; 5] = [None; 5];
    let mut escalations: [u64; 5] = [0; 5];
    for (id, _p) in domains {
        baseline[id as usize] = Some(k.domain(id).unwrap().mask().bits());
    }

    let mut rng = Rng(0x5EED_5702_0000_0001);
    let mut buf64 = [0u8; 64];
    let mut buf256 = [0u8; 256];
    let (mut ok, mut refused) = (0u64, 0u64);
    let mut recreations = 0u64;

    for op in 0..ops {
        let id = 1 + (rng.below(4) as u32);
        // Re-create the domain if a previous SIGKILL tore it down (a
        // spawned child may have taken the id slot in the meantime —
        // then adopt ITS current mask as the fresh baseline).
        if k.domain(id).is_none() {
            let (_, profile) = domains[(id - 1) as usize];
            if k.create_domain_with(id, profile, 0, 0, 0).is_ok() {
                baseline[id as usize] = Some(k.domain(id).unwrap().mask().bits());
                escalations[id as usize] = 0;
                recreations += 1;
            } else {
                baseline[id as usize] = k.domain(id).map(|d| d.mask().bits());
            }
        }
        let r = rng.next();
        let req = match r % 17 {
            0 => SysRequest::Open {
                path: PATHS[rng.below(10) as usize],
                mode: Mode((rng.below(0o777) as u16) | 0o400),
                create: r & 1 != 0,
                read: true,
                write: r & 2 != 0,
                truncate: r & 4 != 0,
            },
            1 => SysRequest::Read {
                fd: rng.byte(),
                buf: &mut buf64,
            },
            2 => SysRequest::Write {
                fd: rng.byte(),
                bytes: &buf256[..rng.below(64) as usize],
            },
            3 => SysRequest::Close { fd: rng.byte() },
            4 => SysRequest::Pipe,
            5 => SysRequest::Dup {
                fd: rng.byte(),
                new_fd: rng.byte(),
            },
            6 => SysRequest::Kill {
                target: (rng.below(40)) as u32,
                sig: rng.below(72) as u8,
            },
            7 => SysRequest::Nanosleep {
                now: r,
                cycles: rng.below(1 << 20),
            },
            8 => SysRequest::SchedYield,
            9 => SysRequest::SigAction {
                signum: rng.below(72) as u8,
                handler: rng.next(),
                restorer: rng.next(),
            },
            10 => SysRequest::Chroot {
                path: PATHS[rng.below(10) as usize],
            },
            11 => SysRequest::Mkdir {
                path: PATHS[rng.below(10) as usize],
                mode: Mode((rng.below(0o777) as u16) | 0o400),
            },
            12 => SysRequest::Unlink {
                path: PATHS[rng.below(10) as usize],
            },
            13 => SysRequest::ListDir {
                fd: rng.byte(),
                buf: &mut buf256,
            },
            14 => SysRequest::NetSend {
                len: rng.below(1 << 16) as u32,
            },
            15 => {
                // Mmap: random flags including the W+X attempt, random
                // lens including wraparound shapes.
                let flags = match rng.below(8) {
                    0 => aegis_os::memory::MemFlags::READ,
                    1 => aegis_os::memory::MemFlags::WRITE,
                    2 => aegis_os::memory::MemFlags::READ | aegis_os::memory::MemFlags::WRITE,
                    3 => aegis_os::memory::MemFlags::READ | aegis_os::memory::MemFlags::EXEC,
                    4 => {
                        aegis_os::memory::MemFlags::READ
                            | aegis_os::memory::MemFlags::WRITE
                            | aegis_os::memory::MemFlags::EXEC
                    } // the W+X attempt
                    5 => aegis_os::memory::MemFlags::EXEC, // X-only attempt
                    _ => aegis_os::memory::MemFlags::READ | aegis_os::memory::MemFlags::EXEC,
                };
                let len = match rng.below(8) {
                    0 => 0,
                    1 => 4096,
                    2 => 4097,              // unaligned
                    3 => usize::MAX,        // wraparound
                    4 => usize::MAX - 4095, // exactly page-unaligned max
                    _ => (rng.below(64) as usize) * 4096,
                };
                let addr = (rng.below(1 << 32) as usize) * 4096;
                SysRequest::Mmap { addr, len, flags }
            }
            _ => {
                // The F13 stubs + IPC: gate-counted, NotImplemented.
                match rng.below(4) {
                    0 => SysRequest::Spawn {
                        cmd: rng.below(1 << 16) as u32,
                    },
                    1 => SysRequest::IpcSend {
                        channel: rng.below(1 << 16) as u32,
                        len: rng.below(1 << 16) as u32,
                    },
                    2 => SysRequest::IpcRecv {
                        channel: rng.below(1 << 16) as u32,
                    },
                    _ => SysRequest::Munmap {
                        addr: (rng.below(1 << 32) as usize) * 4096,
                        len: (rng.below(64) as usize) * 4096,
                    },
                }
            }
        };
        match k.syscall(id, req) {
            Ok(_) => ok += 1,
            // Gate denials (mask/quarantine/bad-nr) and typed executor
            // refusals are both fine; a panic is not — reaching the
            // next line at all is the zero-panics half of the bar.
            Err(_) => refused += 1,
        }

        // The LIVE invariant sweep: every 2000 ops and at the end.
        if op % 2000 == 1999 || op == ops - 1 {
            for (id, _p) in domains {
                if let Some(d) = k.domain(id) {
                    let bits = d.mask().bits();
                    let base = baseline[id as usize].expect("a live domain must have a baseline");
                    assert!(
                        bits & base == bits,
                        "op {op}: domain {id}'s mask WIDENED: {bits:#x} ⊄ {base:#x}"
                    );
                    let esc = d.stats.escalation_attempts;
                    assert!(
                        esc >= escalations[id as usize],
                        "op {op}: domain {id}'s escalation counter went backwards"
                    );
                    escalations[id as usize] = esc;
                }
            }
        }
    }

    // The reviewer's bar, stated: zero panics (reaching here proves
    // it), zero mask-widening (the sweep proved it live), and the
    // storm must have been real: mixed outcomes, kills absorbed.
    assert_eq!(ok + refused, ops as u64);
    assert!(ok > 0, "the storm never produced a success");
    assert!(refused > 0, "the storm never produced a refusal");
    println!(
        "syscall storm: {ops} ops, {ok} ok, {refused} refused, {recreations} domains re-created after kills"
    );
}
