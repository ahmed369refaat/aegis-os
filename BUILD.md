# Building and wiring the netstack into AegisOS (K24)

The stack is a pure library (`src/netstack/`, `no_std`, `no_alloc`,
zero dependencies, zero `unsafe`). It compiles for the host (tests) and
for the kernel's `x86_64-unknown-none` target without modification —
there is no cfg ladder beyond `cfg(test)`.

## 1. Quick verification (host)

```sh
# the module + integration suites (57 tests, deterministic, ~0.1 s)
cargo test -p aegis-os --lib netstack

# the lint lanes the CI gates run
cargo clippy -p aegis-os --all-targets -- -D warnings
cargo clippy -p aegis-kernel --release --target x86_64-unknown-none -- -D warnings
cargo fmt --all --check
```

The tests are deterministic: the clock is a hand-driven `u64`, the
entropy source is a seeded xorshift, and the "wire" is two stacks whose
`FrameSink`s feed each other. No sleeps, no real time, no network.

## 2. Where the stack runs

**Inside the `netd` domain (or a dedicated `tcpip` domain), never the
kernel.** The stack owns frame parsing and connection state; the domain
owns the event loop; the BROKER owns the wire (THREAT_MODEL.md §6):

```
ring-3 user domains
    │  sockets API → syscalls (capability-checked per domain)
    ▼
NetStack (in netd)  ──FrameSink──▶  Broker (SYS_NET_SEND: token bucket,
    ▲  on_frame / poll              per-domain accounting, 1514 B cap)
    │                                        │
    └──────────── driver domain ◀────────────┘
                  (virtio-net rings: vnetdom)
```

## 3. The syscall surface the domain needs

`netd_profile` (src/profile.rs) already carries the arms:

| Syscall | nr | Role for the stack |
|---|---|---|
| `SYS_NET_SEND` | 9 | Egress: every frame the stack emits, through the broker's token bucket |
| `SYS_NET_RECV` | 10 | Ingress: frames the driver domain deposited |
| `SYS_READ`/`SYS_WRITE`/`SYS_OPEN` | — | Config (interface, address) from the ramfs |
| `SYS_IOCTL`/`SYS_PARK`/`SYS_EXIT` | — | The domain's existing runtime arms |

No new syscalls are REQUIRED for the stack itself: the five-argument
sockets surface (below) can ride the existing `SYS_NET_SEND`/`RECV`
mailbox convention the domain already speaks (fd + op word + args in the
data page), which is how `vnetd` already multiplexes DHCP.

### The user-facing sockets surface (mapping)

The stack's API is the semantic definition (`src/netstack/socket.rs` +
`NetStack::` methods); the syscall boundary is a thin marshaller:

| POSIX call | NetStack method | errno surface |
|---|---|---|
| `socket(AF_INET, SOCK_STREAM\|SOCK_DGRAM, 0)` | `socket(domain, kind)` | EMFILE on quota/table |
| `bind(fd, port)` | `bind(domain, fd, port)` | EADDRINUSE, EOPNOTSUPP |
| `listen(fd, backlog)` | `listen(domain, fd, port)` | EADDRINUSE (backlog clamped to the fixed 4) |
| `connect(fd, ip, port)` | `connect(now, sink, domain, fd, ip, port)` | EINPROGRESS; ECONNREFUSED on the RST; ETIMEDOUT on retransmission exhaustion |
| `accept(fd)` | `accept(domain, fd)` | EAGAIN when nothing is established |
| `send(fd, buf)` | `send(now, sink, domain, fd, buf)` | partial writes; EAGAIN when window+ring stall; EMSGSIZE over the datagram cap |
| `recv(fd, buf)` | `recv(domain, fd, buf)` | EAGAIN when empty; 0 = EOF (FIN) |
| `close(fd)` | `close(now, sink, domain, fd)` | FIN (or RST half-open), fd freed immediately |

Every error maps through the ONE errno table
(`netstack::error::errno`) — the boundary translates, it never invents
codes. All operations are non-blocking by construction (the stack has no
sleep primitive).

## 4. Wiring the stack into the domain

```rust
// (inside the netd domain's main loop — sketch of the whole glue)
use aegis_os::netstack::{FrameSink, Entropy, IfCfg, NetStack, MacAddr};

/// The ONLY egress door: the broker syscall. Every frame the stack
/// emits goes through here — the token bucket and per-domain
/// accounting sit under every byte (THREAT_MODEL.md §6).
struct BrokerSink { domain_socket: u32 }
impl FrameSink for BrokerSink {
    fn send_frame(&mut self, frame: &[u8]) -> netstack::Result<()> {
        sys_net_send(self.domain_socket, frame)   // SYS_NET_SEND (nr 9)
            .map_err(|e| map_net_error(e))         // RateLimited → EAGAIN shape
    }
}

/// The clock: ms ticks from the domain's time source (the same
/// tick counter the driver stack already maintains).
fn now_ms() -> u64 { /* the domain's monotonic tick / TIMER tick */ }

/// The entropy: fold the same per-boot entropy the domain already
/// draws (RDRAND-backed, or the seed the kernel passed at spawn).
struct DomainEntropy { state: u32 }
impl Entropy for DomainEntropy { fn next_u32(&mut self) -> u32 { /* ... */ } }

let cfg = IfCfg {
    mac: MacAddr(driver_mac()),          // from the DHCP/config stage
    ip: leased_ip(), netmask: [255,255,255,0], gateway: leased_gw(),
};
let mut stack = NetStack::new(cfg, DomainEntropy::seeded());
let mut sink = BrokerSink { domain_socket: broker_fd };

loop {
    // 1. Ingress: every frame the driver delivered (SYS_NET_RECV).
    while let Some(frame) = sys_net_recv() {
        let _ = stack.on_frame(now_ms(), &mut sink, &frame);
    }
    // 2. Timers: retransmissions, delayed ACKs, window updates,
    //    persist probes, ARP retries, reassembly and TIME_WAIT expiry.
    let _ = stack.poll(now_ms(), &mut sink);
    // 3. User work: drain the sockets mailbox (the marshaller calls
    //    stack.socket/bind/listen/connect/accept/send/recv/close).
    drain_sockets_mailbox(&mut stack, &mut sink, now_ms());
    park_until_event();   // the domain's existing wait primitive
}
```

**Rules the glue must keep (they are what the threat model promises):**

1. The `FrameSink` impl MUST call the broker — never the virtio rings
   directly. The broker is the rate limit and the accounting; bypassing
   it is the one architectural sin the stack cannot defend against from
   inside.
2. `on_frame` and `poll` need the SAME clock value style (monotonic
   ms). Late ticks are late, not lost — every deadline is absolute.
3. `poll` must run at least a few times per second (the delayed-ACK is
   40 ms; the RTO floor is 1 s). One park-wakeup per driver receive
   plus a 250 ms idle timer is plenty.
4. `Entropy` must be per-boot unpredictable (fold a real source). A
   constant seed turns the ISN mixer into a known function.

## 5. Integration steps (the K25 candidate list)

This round ships the stack as a fully tested library inside the
`aegis-os` crate (compiled by both clippy lanes, 57/57 tests). The
remaining VM work, in dependency order:

1. **The `BrokerSink` + `DomainEntropy` glue** in `kernel-x86_64/`
   `drvstack/vnetdom.rs`'s user side (the netd blob grows the stack via
   the registry's exec image discipline — the SERVICE contract's
   2 MiB leaf has room for ~60 KiB of stack state; the TCB pool is the
   big block and is `.bss`-friendly).
2. **The sockets mailbox**: extend the existing `SYS_NET_SEND`/
   `SYS_NET_RECV` data-page convention with a sockets op word (fd,
   op, args) so user domains reach the stack's API — the kernel side
   routes by domain and the stack enforces the per-domain quota.
3. **A boot lane marker** (`[NET] tcp/ip stack: N connections, M
   sockets`) asserted by `boot.sh --verify` the way the `[PKG]` lanes
   are — the VM-side proof that the stack runs at CPL=3 through the
   broker.
4. **DHCP feeding `IfCfg`** (the DHCP state machine the driver domain
   already runs becomes the config source for `NetStack::new`).

## 6. Capacity constants (the memory bill)

| Structure | Size | Count | Total |
|---|---|---|---|
| TCB (2 KiB rings + state) | ~2.1 KiB | 8 | ~17 KiB |
| Socket entries (UDP queue inline) | ~2.2 KiB | 16 | ~35 KiB (only as opened) |
| Reassembly slots | 1.5 KiB | 4 | 6 KiB |
| ARP cache | 32 B | 16 | 512 B |
| TCP tx scratch | 1514 B | 1 | 1.5 KiB |

Total worst case ≈ 60 KiB of fixed `.bss`-style state — comfortably
inside the SERVICE contract's 8 MiB no_alloc stack and 128-page cage
(the K22 lesson: the image fits the cage or the exec refuses, loudly).
