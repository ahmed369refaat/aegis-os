# AegisOS netstack — Threat Model (K24)

**Scope:** `src/netstack/` — the TCP/IP stack for the `netd` (or dedicated
`tcpip`) domain. Every claim below names the code that enforces it and the
test that proves it (`src/netstack/tests/mod.rs`).

**Trust boundary:** every byte entering `NetStack::on_frame` is hostile —
truncated, spoofed, replayed, overlapping, checksum-correct-but-lying. The
stack's own memory (fixed tables, rings, pools) is the protected surface.

---

## 1. Malformed packet injection (overread / overwrite / panic)

**The invariant:** no untrusted length field ever extends a slice, and no
malformed packet can panic the stack (the contract's "no `panic!` on
untrusted input").

**Enforcement (layer by layer, in validation order):**

| Layer | Checks (before any field is trusted) | Code |
|---|---|---|
| Ethernet | ≥ 14 B, ≤ 1514 B | `ethernet.rs::EthFrame::parse` |
| ARP | ≥ 28 B, htype=1, ptype=IPv4, hlen=6, plen=4, op ∈ {1,2} | `arp.rs::ArpPacket::parse` |
| IPv4 | ≥ 20 B, version=4, 5 ≤ ihl ≤ 15, ihl·4 ≤ buf, total_len ≥ ihl·4, **total_len ≤ buf**, header checksum | `ipv4.rs::Ipv4Packet::parse` |
| Fragment | offset·8 in checked arithmetic, end ≤ 1480, non-final fragments 8-aligned | `ipv4.rs::ReasmSlot::feed` |
| ICMP | ≥ 8 B, message checksum | `icmp.rs::IcmpPacket::parse` |
| UDP | ≥ 8 B, length ≥ 8, **length ≤ IP payload** | `udp.rs::UdpDatagram::parse` |
| TCP | ≥ 20 B, 5 ≤ data_offset, data_offset·4 ≤ buf, segment checksum (pseudo-header) | `tcp.rs::TcpSegment::parse` |

**Design rules that make the invariant structural:**

- All output writes are bounds-checked BEFORE the first byte
  (`ethernet.rs::emit`, `ipv4.rs::emit_header`, every TCP builder).
- All sequence arithmetic is the RFC 793 wrapping form
  (`tcp.rs::seq_lt`/`seq_le`); a raw `<` on sequence numbers does not exist.
- All index math is `checked_*`/`saturating_*`; the byte rings mask by
  power-of-two capacity.
- Zero `unsafe` in the entire stack (no `static mut`, no pointer casts):
  there is no UB surface to reach from untrusted input.

**Proof:** `malformed_frames_never_panic_never_reply` feeds truncated
ethernet, unknown EtherType, checksum-corrupted IPv4, 4-byte "TCP" and
protocol 99 — every one is a counted drop, nothing is answered, nothing
panics. Per-layer unit tests pin each gate
(`truncated_frame_is_refused_before_any_field_is_trusted`,
`total_len_lies_are_refused`, `corrupted_checksum_refused`, …).

---

## 2. IP fragmentation attacks (teardrop, ping of death)

**Teardrop (overlap):** ANY intersection between a new fragment's
`[start, end)` and a tracked range refuses the **whole datagram** — slot
dropped, counted (`ipv4.rs::ReasmSlot::feed`, `Error::FragmentOverlap`).
The stack does not "handle" overlaps by believing any byte order; overlap
IS attack traffic. **Proof:** `overlapping_fragments_kill_the_datagram_over_the_wire`
— the datagram vanishes, the slot frees, nothing is delivered.

**Ping of death / oversize reassembly:** the slot cap is
`MAX_REASM_DATAGRAM = 1480` bytes. A fragment whose computed end exceeds
the cap is refused (`Error::DatagramTooLarge`); the `16-bit length field
+ 13-bit offset` arithmetic makes >65535 impossible anyway, and 1480 is
far below that. **Proof:** `oversized_reassembly_refused`.

**Incomplete-fragment memory squats:** 4 slots
(`MAX_REASM_SLOTS`), each dying at an absolute 10 s deadline
(`REASM_TIMEOUT_MS`) swept by `poll`. A flood of incomplete datagrams
occupies at most 4 × 1480 B and then the fifth datagram is dropped —
memory is O(1) in attacker effort. **Proof:**
`incomplete_fragment_times_out_over_the_wire`.

**Fragment-count bombs:** at most 8 distinct non-overlapping ranges are
tracked per slot (`MAX_FRAG_HOLES`); more → `Error::FragmentHoleCount`,
whole-datagram drop.

---

## 3. SYN floods

Three independent layers, in order (`tcp.rs`):

1. **Per-source rate window** — `SYN_RATE_MAX` (4) SYNs per
   `SYN_RATE_WINDOW_MS` (500 ms) per source IP, tracked in 8 fixed slots;
   over-budget SYNs drop silently. **Proof:**
   `syn_flood_layers_rate_window_and_cookies`: 12 SYNs from one source →
   exactly 4 answered, ≥ 8 dropped, and the TCB pool still holds exactly 4
   entries — not one TCB per SYN.

2. **Half-open budget** — `MAX_HALF_OPEN` (4) TCBs in SYN_RECEIVED
   stack-wide; the accept queue is `LISTEN_BACKLOG` (4) deep. Both bounds
   are the fixed cost of the listen() call, not of the flood.

3. **SYN cookies** — when the budget is spent, the SYN-ACK's ISN IS the
   cookie: `syn_cookie(secret, remote_ip, remote_port, local_port,
   time_bucket)` — a per-boot-secret keyed mixing function over the
   4-tuple and a 64 s time bucket. **No TCB, no queue slot, no buffer is
   spent.** The connection materializes ONLY when an ACK returns whose
   acknowledgement number proves possession of the cookie (validated
   against the current AND previous time bucket — `try_cookie_completion`).
   A materialized connection evicts a half-open entry if the queue is full
   (a completed handshake outranks a pending one).

**Why cookies and not a SYN cache:** a SYN cache still spends memory per
source (an attacker with N source addresses — or a spoofed-source flood —
pays N entries). The cookie path spends ZERO per-source state: the flood's
cost is one rate-window slot and one SYN-ACK emission (rate-bounded by
the RST/cookie path and the broker). The tradeoff is honest: cookie
connections lose the original SYN's options (we re-derive MSS from
defaults) and cannot be validated for non-TCP... none of which exists
here.

**Proof:** `syn_cookie_completes_a_connection` — the honest client's
handshake completes THROUGH a cookie under flood, the TCB materializes on
the returning ACK, and data flows. `syn_cookies_completed`/`issued`
counters track both halves.

**Spoofed-source SYNs** (blind floods): no state is allocated for them at
all in cookie mode — the cookie's ACK must come from the same 4-tuple the
cookie named, which a spoofer cannot produce for someone else's
connection... and a spoofer "completing" its own cookie merely creates a
connection to itself (harmless, and bounded by the pools).

---

## 4. TCP sequence number prediction

**ISN generation:** `TcpLayer::next_isn` mixes the per-boot secret (four
entropy draws folded at construction), a 1 s-granularity clock term, a
per-boot counter, and the remote 4-tuple. Consecutive connections to the
same peer get unrelated ISNs; an off-path attacker that observes one ISN
learns nothing about the next (the counter and clock re-key every mix).

**Blind resets are also sequence-gated:** an RST is only accepted when it
passes the state-appropriate test — in SYN_SENT, `ack == snd_nxt`
exactly; otherwise the RFC 793 in-window test against `snd_una..snd_nxt`
(ACK-bearing) or `rcv_nxt..rcv_nxt+window` (bare). A blind RST with a
guessed sequence outside those ranges is a counted drop
(`tcp.rs::on_segment_for_tcb`). This matters more than ISN randomness for
this OS: the window is small (1024 B ⇒ ~1/2³² of the sequence space per
guess... the 16-bit window / 2³² ≈ 1/65536 per RST; the in-window test is
the gate either way).

**Proof:** `sequence_arithmetic_wraps_correctly` pins the comparison
semantics across the 2³² seam; `socket_api_error_paths` proves the
LEGITIMATE refusal RST (correct ack) tears down SYN_SENT with
ECONNREFUSED — i.e., the acceptance test lets the right shape through and
(by construction) rejects the wrong ones.

---

## 5. Resource exhaustion

Everything is a fixed table with a loud refusal:

| Resource | Bound | Refusal (errno) |
|---|---|---|
| TCBs | `MAX_TCBS = 8` | EMFILE |
| Listeners | 4 | EMFILE |
| Accept queue / half-open | 4 / 4 | cookies (no allocation) |
| Sockets | 16 total, 6 per domain, 8 tracked domains | EMFILE (`DomainQuota`) |
| Send ring / TCB | 1024 B | partial write, then EAGAIN |
| Receive ring / TCB | 1024 B | window closes to 0 |
| UDP queue | 4 × 512 B per socket | drop-new + count |
| ARP cache | 16 entries, 60 s TTL | oldest-expiry eviction |
| ARP pending TX | 1 slot | `ArpQueueFull` |
| Reassembly | 4 × 1480 B, 10 s | drop + count |
| ICMP error bucket | 5, +1/s | silent |
| RST bucket | 5 / s | silent |
| Event queue | 16 | missed event → next poll re-derives |
| TIME_WAIT | 2×MSL = 120 s absolute | expiry frees the slot |

There is **no allocation anywhere** in the stack: exhaustion is a
`Result`, never an OOM and never an unbounded queue. **Proof:**
`tcb_pool_exhausts_cleanly` (9th connect → EMFILE, no panic),
`socket_table_and_domain_quota_exhaust` (per-domain quota, then the
tracked-domain cap — and one domain's flood does not consume another
domain's slots), `window_full_stalls_then_drains` (the flow-control bound
itself: ≥ 1024 B accepted, then EAGAIN; every byte drains byte-exact).

**Bounded lifetimes:** ARP entries (60 s), reassembly slots (10 s),
TIME_WAIT (120 s), delayed ACKs (40 ms), persist probes (5 s), RTO
(1 s → 60 s backoff, 6 tries → ETIMEDOUT). No state lives forever.

---

## 6. Broker bypass

**The invariant: the stack cannot emit a frame except through the
caller-supplied [`FrameSink`].**

- The stack owns no device access — it is a library inside the netd
  domain; the ONLY egress type is `FrameSink::send_frame`.
- Every emission path funnels through it: `TcpLayer::build_and_send`,
  `send_synack_cookie`, `maybe_send_rst` (TCP), `NetStack::transmit_ipv4`
  (UDP/ICMP), `ArpLayer::transmit` (ARP). Each writes a complete frame
  into a local scratch and hands it to the sink — there is no second
  door to forget to close.
- In the domain, the `FrameSink` impl wraps the broker syscall
  (`SYS_NET_SEND`): the kernel's token bucket, per-domain accounting and
  the `MAX_NET_FRAME_BYTES` cap sit under every byte (BUILD.md §wiring).
  The kernel enforces this independent of the stack's cooperation — the
  `netd_profile` is the only profile with the send arm, and the broker
  itself rate-limits regardless of caller.
- Egress refusals (`Error::RateLimited`) are surfaced, never retried
  covertly: the stack's own timers re-drive transmission at the
  transport layer (bounded, counted in `stats.egress_refused`).

**Proof:** `broker_exhaustion_surfaces_and_nothing_bypasses_the_sink` —
a budget-capped sink refuses egress; the refusal surfaces verbatim
(`RateLimited` with the counts), the stack's counters account for every
attempt, and a zero-budget sink blocks the very first ARP request. The
deterministic two-stack harness (`pump`) also proves every test byte
travelled sink → `on_frame` → sink — there is no other route for the
tests to observe.

---

## 7. ICMP-specific attacks

**Amplification (error/reply mirroring):** two token buckets bound
generation — errors (unreachable): 5 at once, +1/s; echo replies: 10 at
once, +2/s (`icmp.rs::IcmpLimiter`). A closed-port scan or a
spoofed-source ping flood gets a trickle, never a mirror. Echo replies
carry EXACTLY the request's payload bytes (a 64 B ping answers 64 B).
Replies go to the request's SOURCE, never to a broadcast address.

**ICMP error ping-pong:** unreachables are generated ONLY from the
UDP/TCP dispatch (a closed port), never from ICMP input — an error
answering an error is structurally impossible.

**ICMP redirect:** IGNORED, by policy (`IcmpKind::Ignored` → counted).
This stack's next hop comes from the operator's interface config
(`IfCfg::next_hop`), not from the wire. The classic redirect-based
MITM (an attacker announcing a "better route") has no code path to
influence — there is nothing to disable.

**Spoofed unreachable vs live connections:** received unreachables are
DIAGNOSTICS ONLY (a counter) — no TCP state is torn down on them. A
blind "host unreachable" naming a live connection is the classic
connection-kill; here it costs the attacker one packet and us one
counter increment. Connections die by retransmission exhaustion
(`ETIMEDOUT`) or explicit RST with a valid sequence — or not at all.

---

## 8. ARP-specific attacks

**Poisoning (spoofed replies):** bounded and self-healing — the cache is
16 fixed entries with a 60 s absolute TTL (`ENTRY_TTL_MS`); a poisoned
mapping ages out and the stack re-asks. A gratuitous announcement can
refresh or take a free slot but never grows the table. Worst case per
successful spoof: 60 s of misdirected egress — and the next-hop policy
for off-link destinations still routes via the operator's gateway.

**ARP floods:** one in-flight request at a time (`MAX_ARP_RETRIES` = 3,
1 s apart, then `TimedOut`), one parked TX datagram. Unresolvable
destinations cost one request's worth of state, not one per attempt.

**Gratuitous ARP:** accepted (the legitimate use: announcing address
changes on link) with the same TTL and table bounds as any reply
(`arp.rs::tests::gratuitous_announcement_is_cached_and_bounded`).

---

## 9. Found-live bugs (the reason these mechanisms are what they are)

The integration suite drove out four real bugs before delivery — each
now pinned by a test and named in the code:

1. **Reassembly "completion" without the final fragment**
   (`ipv4.rs`): a single range starting at 0 looked complete. Fixed with
   the `final_end` oracle (the MF=0 fragment's end must equal the
   covered total). Test: `reassembly_two_fragments_complete` (first
   fragment alone → `None`).
2. **Cookie SYN-ACK data_offset = 5 with a 4-byte MSS option**
   (`tcp.rs::send_synack_cookie`): the peer parsed the option bytes as
   payload — the cookie's ack was off by exactly 4. Fixed (offset 6).
   Test: `syn_cookie_completes_a_connection` (completed = 1).
3. **FIN acks never advanced `snd_una`** (`tcp.rs`): advancement was
   capped by the send ring's contents, but a FIN consumes sequence
   space without a ring byte — both teardowns wedged
   (CLOSING/LAST_ACK forever). Fixed: advance in sequence space.
   Test: `tcp_handshake_data_teardown` (all TCBs reach CLOSED, both
   stacks).
4. **Retransmission desync + zero-window deadlock** (`tcp.rs`):
   `retransmit()` could send unsent ring bytes without advancing
   `snd_nxt` (the receiver ran ahead of the sender; acks became
   unacceptable forever), and a payload-less persist probe plus no
   window-update ACKs meant a drained zero-window peer never learned
   the window had opened. Fixed: retransmit bounded to
   `[snd_una, snd_nxt)`, window tracking on every acceptable segment,
   window-update ACKs on drain, a 1-byte persist probe, and
   poll-driven transmission. Test: `window_full_stalls_then_drains`
   (2048 B accepted → 2048 B delivered byte-exact through a stall).

---

## 10. Deliberate non-goals (honesty section)

- **No out-of-order receive queue:** in-order delivery only; gaps are
  duplicate-ACKed and retransmitted (Go-Back-N). Cost: throughput on
  lossy links, not correctness — and no reorder buffer to bound.
- **No IPv6, no TCP options beyond MSS, no timestamps/SACK/W_SCALE:** the
  window is the fixed 1 KiB ring; a 64 KiB window without scaling is
  unreachable by design.
- **No RTT estimator:** the RTO is fixed-1 s with exponential backoff
  (RFC 6298's shape without the variance math).
- **The ISN mixer is a mixing function, not a CSPRNG** (§4 states what
  that buys and what it does not; the entropy trait lets the domain back
  it with a real DRBG).
- **The cookie is a keyed mix, not a MAC** — same reasoning, same
  upgrade path via `Entropy`.
- **Forwarding:** none. The stack never re-emits a transit packet — one
  amplifier surface closed by construction.
