//! K27: TLS 1.3 LIVE over the kernel's own TCP/IP stack — the round
//! the transport-security gap closed.
//!
//! The proof (one step, the e1k discipline + the netstack + the tls
//! crate): claim the e1000, broker-map the rings, program RX/TX,
//! run the K24 netstack (ARP → TCP) over the NIC through QEMU's
//! slirp to a REAL OpenSSL server on the host (the lane's
//! `scripts/tls_echo_server.py`), drive the FULL TLS 1.3 client
//! handshake — X25519 ECDHE, the key schedule, ChaCha20-Poly1305
//! records, the PINNED Ed25519 CertificateVerify, both Finished
//! MACs — then one encrypted request and the encrypted echo back,
//! decrypted and checked in the kernel. Loud markers at every
//! gate; the teardown is the session discipline's.
//!
//! The client's randomness is FIXED here (the host fixture test
//! pins the same values): the proof is deterministic and
//! replayable; a production caller seeds them from the boot entropy
//! source.
//!
//! The RX ring discipline (the round's live-lane bug): the DD poll
//! covers ALL sixteen descriptors — a completed frame lands at
//! whichever slot the device chose, and a poll watching one slot
//! starves the rest. Each slot has its own buffer (two slots share
//! one 4 KiB frame: offsets 0 and 1520), and RDT only ever ADVANCES
//! (a tail written backwards empties the ring — nothing leaves).

use crate::frames::FramePool;
use crate::strutil;
use crate::strutil::line;

/// The domain id that owns the socket (the netstack's per-domain
/// capability).
const TLS_DOMAIN: u32 = 77;

/// The slirp gateway IS the host: 10.0.2.2 reaches the lane's echo
/// server.
const HOST: [u8; 4] = [10, 0, 2, 2];
/// Our address in slirp's net (the DHCP proof lands 10.0.2.15).
const OUR_IP: [u8; 4] = [10, 0, 2, 15];
const NETMASK: [u8; 4] = [255, 255, 255, 0];
/// The echo server's port on the host.
const ECHO_PORT: u16 = 44333;

/// The pinned Ed25519 key (tls/tests/server-cert.pem's SPKI — the
/// same trust anchor the host fixture test verifies).
const PIN: [u8; 32] = [
    0x33, 0x6a, 0x06, 0xe3, 0xf7, 0xa9, 0xc2, 0x10, 0xad, 0xc9, 0x5d, 0xcb, 0xed, 0xdb, 0x98, 0x0f,
    0x00, 0x25, 0x85, 0xd9, 0x37, 0xbd, 0xe4, 0xca, 0x3d, 0xef, 0xb7, 0xe7, 0xfe, 0x81, 0x6f, 0xc0,
];

/// The client's deterministic inputs (the host fixture's).
const CLIENT_PRIVATE: [u8; 32] = [
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
];
const CLIENT_RANDOM: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];
const SESSION_ID: [u8; 32] = [
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
];

/// e1000 register offsets (the e1k module's set).
const E1K_RCTL: u64 = 0x0100;
const E1K_TCTL: u64 = 0x0400;
const E1K_RDBAL: u64 = 0x2800;
const E1K_RDLEN: u64 = 0x2808;
const E1K_RDT: u64 = 0x2818;
const E1K_TDBAL: u64 = 0x3800;
const E1K_TDLEN: u64 = 0x3808;
const E1K_TDH: u64 = 0x3810;
const E1K_TDT: u64 = 0x3818;
/// Descriptors per ring.
const E1K_NDESC: u64 = 16;
/// The RX buffer stride: two buffers per 4 KiB frame.
const RX_STRIDE: u64 = 1520;

/// The frame owner tag.
pub const TLS_OWNER: u32 = 78;

/// Deterministic entropy (the ISN seed — the proof is replayable).
struct SeedRng(u32);
impl aegis_os::netstack::Entropy for SeedRng {
    fn next_u32(&mut self) -> u32 {
        // xorshift32 — deterministic, no secrets in a proof
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }
}

/// The egress door: one frame per TX descriptor, the DD poll after
/// each — the e1k CPL0 proof's discipline (the broker contract's
/// single door, the kernel's token bucket under every byte). TDT
/// may only ADVANCE; every slot shares the one TX buffer — the DD
/// poll proves the device finished its DMA read before the next
/// frame overwrites it (serialized reuse).
struct E1kTx<'a> {
    bus: &'a crate::mmio::BarMmio,
    tx_ring: u64,
    tx_buf: u64,
    tx_next: u32,
    tx_errors: u32,
    sent: u32,
}

impl aegis_os::netstack::FrameSink for E1kTx<'_> {
    fn send_frame(&mut self, frame: &[u8]) -> aegis_os::netstack::error::Result<()> {
        use crate::mmio::MmioBus;
        use aegis_os::netstack::error::Error;
        if frame.len() > 1514 {
            self.tx_errors += 1;
            return Err(Error::FrameTooLong {
                len: frame.len(),
                max: 1514,
            });
        }
        let slot = self.tx_next as u64;
        let desc = self.tx_ring + slot * 16;
        self.tx_next = (self.tx_next + 1) % 16;
        // copy into THE tx buffer — every slot shares it: the DD poll
        // below proves the device finished its DMA read of the
        // previous frame before we overwrite (serialized reuse).
        for (i, b) in frame.iter().enumerate() {
            crate::drvstack::netutil::put8(self.tx_buf + i as u64, *b);
        }
        // desc: buffer, length, EOP|IFCS|RS
        crate::memops::write_u64(desc, self.tx_buf);
        crate::memops::write_u32(desc + 8, frame.len() as u32);
        crate::memops::write_u32(desc + 12, 0);
        crate::drvstack::netutil::put8(desc + 11, 0x0B);
        // the tail kick — always forward, wrapping at the ring size
        if !self.bus.write32(E1K_TDT, self.tx_next) {
            self.tx_errors += 1;
            return Err(Error::SendStalled);
        }
        // poll the DD write-back (bounded)
        let mut spins = 0u64;
        while crate::virtio::read_u8_pa(desc + 12) & 1 == 0 && spins < 50_000_000 {
            spins += 1;
        }
        if crate::virtio::read_u8_pa(desc + 12) & 1 == 0 {
            self.tx_errors += 1;
            return Err(Error::SendStalled);
        }
        // clean the status for this slot's next use
        crate::drvstack::netutil::put8(desc + 12, 0);
        self.sent += 1;
        Ok(())
    }
}

/// K27: the live TLS round trip.
#[cfg(not(test))]
pub(crate) fn tls_step<const N: usize>(
    k: &mut aegis_os::Kernel<N>,
    pool: &mut FramePool<N>,
    out: &mut dyn FnMut(&str),
    broker: &mut aegis_os::dma::DmaBroker<crate::arch::vtd::Vtd>,
    inv: &crate::pci::Inventory,
) {
    use crate::mmio::MmioBus;
    use aegis_os::dma::DmaVerdict;
    use aegis_os::netstack::error::Error as NetError;
    use aegis_os::netstack::{IfCfg, NetStack};

    let Some(dev) = inv.find_by(0x8086, 0x02) else {
        line(out, &["[TLS] no e1000 on this machine — the step skips"]);
        return;
    };
    if matches!(broker.verdict(), DmaVerdict::Absent { .. }) {
        line(out, &["[TLS] broker verdict absent — refusing"]);
        return;
    }
    let Some(bar) = crate::pci::mem_bar(dev, 0) else {
        line(out, &["[TLS] BAR0 unresolved — refusing"]);
        return;
    };
    let Some(bus) = crate::mmio::BarMmio::new(bar.base, bar.size) else {
        line(out, &["[TLS] BAR0 window malformed — refusing"]);
        return;
    };
    // the MAC (RAL/RAH) — the stack's link identity
    let (Some(ral), Some(rah)) = (bus.read32(0x5400), bus.read32(0x5404)) else {
        line(out, &["[TLS] MAC read refused — refusing"]);
        return;
    };
    let mac = aegis_os::netstack::ethernet::MacAddr([
        (ral & 0xFF) as u8,
        ((ral >> 8) & 0xFF) as u8,
        ((ral >> 16) & 0xFF) as u8,
        ((ral >> 24) & 0xFF) as u8,
        (rah & 0xFF) as u8,
        ((rah >> 8) & 0xFF) as u8,
    ]);
    crate::pci::enable_mem(dev);

    // ── the session + frames (the e1k discipline) ──
    // 11 frames: rx ring, tx ring, tx buffer, and 8 RX buffers (two
    // 1514-byte slots each, offsets 0 and 1520).
    let mut session = crate::session::DriverSession::new(
        k,
        pool,
        broker,
        Some(dev),
        TLS_OWNER,
        dev.dom,
        false,
        "[TLS] teardown",
        "",
    );
    let mut frames = [0u64; 11];
    for slot in frames.iter_mut() {
        match session.frame() {
            Ok(pa) => *slot = pa,
            Err(_) => {
                line(out, &["[TLS] pool exhausted — refusing"]);
                return;
            }
        }
    }
    let [rx_ring, tx_ring, tx_buf, rxb0, rxb1, rxb2, rxb3, rxb4, rxb5, rxb6, rxb7] = frames;
    let rxbufs = [rxb0, rxb1, rxb2, rxb3, rxb4, rxb5, rxb6, rxb7];
    for &pa in frames.iter() {
        if session.map(pa).is_none() {
            line(out, &["[TLS] broker refused a frame — refusing"]);
            return;
        }
    }
    // program the RX ring: every slot armed with its own buffer
    // (slot n → frame n/2 at offset (n%2)*1520)
    let rx_prog = [
        (E1K_RDBAL, rx_ring as u32),
        (E1K_RDBAL + 4, 0),
        (E1K_RDLEN, (E1K_NDESC * 16) as u32),
        (0x2810, 0), // RDH
    ];
    for &(off, v) in rx_prog.iter() {
        if !bus.write32(off, v) {
            line(out, &["[TLS] RX program refused — refusing"]);
            session.close(out);
            return;
        }
    }
    for n in 0..E1K_NDESC {
        let desc = rx_ring + n * 16;
        let buf = rxbufs[(n / 2) as usize] + (n % 2) * RX_STRIDE;
        crate::memops::write_u64(desc, buf);
        crate::memops::write_u32(desc + 8, 0);
        crate::memops::write_u32(desc + 12, 0);
    }
    // RDT = 1: desc 0 available (the lockstep — the tail only ever
    // advances from here)
    if !bus.write32(E1K_RDT, 1) || !bus.write32(E1K_RCTL, 0x8002) {
        line(out, &["[TLS] RX tail refused — refusing"]);
        session.close(out);
        return;
    }
    let tx_prog = [
        (E1K_TDBAL, tx_ring as u32),
        (E1K_TDBAL + 4, 0),
        (E1K_TDLEN, (E1K_NDESC * 16) as u32),
        (E1K_TDH, 0),
        (E1K_TDT, 0),
        (E1K_TCTL, 0x2),
    ];
    for &(off, v) in tx_prog.iter() {
        if !bus.write32(off, v) {
            line(out, &["[TLS] TX program refused — refusing"]);
            session.close(out);
            return;
        }
    }
    // rings mapped — the device may DMA
    crate::pci::enable_bus_master(dev);
    line(
        out,
        &["[TLS] e1000 armed: MAC, RX/TX rings broker-mapped, TCP to 10.0.2.2:44333"],
    );

    // ── the stack + the socket + the connect ──
    let mut stack = NetStack::new(
        IfCfg {
            mac,
            ip: OUR_IP,
            netmask: NETMASK,
            gateway: HOST,
        },
        SeedRng(0x4b27_1337),
    );
    let mut sink = E1kTx {
        bus: &bus,
        tx_ring,
        tx_buf,
        tx_next: 0, // the ring is EMPTY at setup (TDH=TDT=0): the
        // first frame is desc 0
        tx_errors: 0,
        sent: 0,
    };
    let fd = match stack.socket(TLS_DOMAIN, aegis_os::netstack::socket::SOCK_STREAM) {
        Ok(fd) => fd,
        Err(_) => {
            line(out, &["[TLS] socket refused — refusing"]);
            session.close(out);
            return;
        }
    };
    let mut now = 0u64;
    // ArpPending / InProgress are the EINPROGRESS shape — the SYN
    // leaves when the gateway's MAC resolves (the pump finishes it).
    if let Err(e) = stack.connect(now, &mut sink, TLS_DOMAIN, fd, &HOST, ECHO_PORT) {
        if !matches!(
            e,
            NetError::ArpPending | NetError::InProgress | NetError::Again
        ) {
            line(out, &["[TLS] connect refused — refusing"]);
            session.close(out);
            return;
        }
    }

    // ── the TLS client ──
    let cfg = aegis_tls::handshake::ClientConfig {
        client_private: CLIENT_PRIVATE,
        client_random: CLIENT_RANDOM,
        session_id: SESSION_ID,
        pinned_ed25519: PIN,
    };
    let mut client = aegis_tls::handshake::Client::new(cfg);
    let mut outbuf = [0u8; aegis_tls::record::RECORD_CAP + 64];

    // The record reassembly window: TCP stream → records.
    let mut stream = [0u8; 4096];
    let mut stream_len = 0usize;

    // The send queue: records waiting for the TCP window.
    let mut sendq = [0u8; 1024];
    let mut send_len = 0usize;

    // 0 CH pending, 1 flight, 2 done — the client's own phase
    let mut phase_tls = 0u8;
    let mut verified = false;
    let mut echoed = 0usize;
    let mut echo_ok = false;
    let mut app_scratch = [0u8; aegis_tls::record::RECORD_CAP];

    // the RX ring cursor: RDT only advances
    let mut rdt: u32 = 1;
    let mut rx_hits: u64 = 0;

    // ── THE PUMP ──
    let mut cycles = 0u64;
    while cycles < 40_000_000 {
        cycles += 1;
        // the RX poll: EVERY descriptor's DD — a completed frame
        // lands at whichever slot the device chose (the legacy RX
        // write-back: length at +8, status at +12)
        for n in 0..E1K_NDESC {
            let desc = rx_ring + n * 16;
            if crate::virtio::read_u8_pa(desc + 12) & 1 == 0 {
                continue;
            }
            rx_hits += 1;
            let len = crate::memops::read_u16(desc + 8) as usize;
            let n_bytes = core::cmp::min(len, 1514);
            let buf = rxbufs[(n / 2) as usize] + (n % 2) * RX_STRIDE;
            let mut frame = [0u8; 1514];
            for (i, b) in frame.iter_mut().enumerate().take(n_bytes) {
                *b = crate::virtio::read_u8_pa(buf + i as u64);
            }
            // clean the slot and advance the tail — forward only
            crate::memops::write_u32(desc + 8, 0);
            crate::memops::write_u32(desc + 12, 0);
            rdt = (rdt + 1) % 16;
            let _ = bus.write32(E1K_RDT, rdt);
            let _ = stack.on_frame(now, &mut sink, &frame[..n_bytes]);
        }
        let _ = stack.poll(now, &mut sink);
        // REAL time, not a spin counter: the stack's ARP/RTO timers
        // run in milliseconds, and QEMU delivers the first RX only
        // after the RCTL write's 1000ms virtual window — a virtual
        // 1ms-per-cycle clock burns the ARP's retry budget long
        // before any reply lands (the live lane caught it: 15 ARP
        // retries, one reply, no SYN).
        now = (crate::clock::now_ns() / 1_000_000) as u64;

        // drain the socket: recv → the TLS record stream
        loop {
            let mut chunk = [0u8; 512];
            match stack.recv(TLS_DOMAIN, fd, &mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if stream_len + n <= stream.len() {
                        stream[stream_len..stream_len + n].copy_from_slice(&chunk[..n]);
                        stream_len += n;
                    } else {
                        break; // window full: process what we have
                    }
                }
                Err(NetError::Again) => break,
                Err(_) => break,
            }
        }

        // process complete records out of the stream
        let mut consumed = 0usize;
        while stream_len - consumed >= 5 {
            let rl = u16::from_be_bytes([stream[consumed + 3], stream[consumed + 4]]) as usize;
            if consumed + 5 + rl > stream_len {
                break;
            }
            let rec: &[u8] = &stream[consumed..consumed + 5 + rl];
            match client.on_record(rec, &mut app_scratch) {
                Ok(aegis_tls::handshake::Event::Continue) => {}
                Ok(aegis_tls::handshake::Event::ServerVerified) => {
                    verified = true;
                    // queue our Finished
                    let m = client.build_finished(&mut outbuf).unwrap_or(0);
                    if send_len + m <= sendq.len() {
                        sendq[send_len..send_len + m].copy_from_slice(&outbuf[..m]);
                        send_len += m;
                    }
                    // queue the encrypted GET
                    let g = client
                        .seal_app_data(b"GET / HTTP/1.0\r\n\r\n", &mut outbuf)
                        .unwrap_or(0);
                    if send_len + g <= sendq.len() {
                        sendq[send_len..send_len + g].copy_from_slice(&outbuf[..g]);
                        send_len += g;
                    }
                }
                Ok(aegis_tls::handshake::Event::AppData(n)) => {
                    // the echo: check the deterministic head
                    if n >= 5 && app_scratch[..5] == *b"PONG:" && echoed == 0 {
                        echoed = n;
                        echo_ok = true;
                    }
                }
                Ok(aegis_tls::handshake::Event::Alert(l, d)) => {
                    let mut b1 = [0u8; 20];
                    let mut b2 = [0u8; 20];
                    line(
                        out,
                        &[
                            "[TLS] server alert ",
                            strutil::dec(u64::from(l), &mut b1),
                            "/",
                            strutil::dec(u64::from(d), &mut b2),
                            " — LOUD",
                        ],
                    );
                }
                Err(e) => {
                    line(out, &["[TLS] handshake error: ", e.describe(), " — LOUD"]);
                }
            }
            consumed += 5 + rl;
        }
        // shift the remainder
        if consumed > 0 {
            stream.copy_within(consumed..stream_len, 0);
            stream_len -= consumed;
        }

        // the CH: queue as soon as the client can build it
        if phase_tls == 0 {
            if let Ok(n) = client.build_client_hello(&mut outbuf) {
                if send_len + n <= sendq.len() {
                    sendq[send_len..send_len + n].copy_from_slice(&outbuf[..n]);
                    send_len += n;
                    phase_tls = 1;
                }
            }
        }

        // the send queue → the TCP window
        let mut sent = 0usize;
        while sent < send_len {
            match stack.send(now, &mut sink, TLS_DOMAIN, fd, &sendq[sent..send_len]) {
                Ok(n) => sent += n,
                Err(NetError::InProgress) => break,
                Err(NetError::Again) => break,
                Err(_) => break,
            }
        }
        if sent > 0 {
            sendq.copy_within(sent..send_len, 0);
            send_len -= sent;
        }

        if echo_ok {
            break;
        }
    }

    // ── the verdict + teardown ──
    let mut nb = [0u8; 20];
    let cyc = strutil::dec(cycles, &mut nb);
    let mut nb2 = [0u8; 20];
    let ech = strutil::dec(echoed as u64, &mut nb2);
    if verified && echo_ok {
        line(
            out,
            &[
                "[TLS] TLS 1.3 handshake VERIFIED over the kernel's own TCP/IP stack: X25519 + HKDF key schedule + ChaCha20-Poly1305, the server's Ed25519 CertificateVerify against the PINNED key, both Finished MACs — a real OpenSSL peer (",
                cyc,
                " pump cycles)",
            ],
        );
        line(
            out,
            &[
                "[TLS] encrypted round trip: GET out, PONG echo back — ",
                ech,
                " bytes decrypted in the kernel (the transport-security layer is live)",
            ],
        );
    } else if verified {
        line(
            out,
            &[
                "[TLS] handshake verified but the echo did not arrive — LOUD (cycles ",
                cyc,
                ")",
            ],
        );
    } else {
        line(
            out,
            &[
                "[TLS] the live TLS exchange did not complete — LOUD (cycles ",
                cyc,
                ", phase ",
                strutil::dec(u64::from(phase_tls), &mut [0u8; 20]),
                ", stream ",
                strutil::dec(stream_len as u64, &mut [0u8; 20]),
                ", tx ",
                strutil::dec(u64::from(sink.sent), &mut [0u8; 20]),
                "/",
                strutil::dec(u64::from(sink.tx_errors), &mut [0u8; 20]),
                ", rx ",
                strutil::dec(rx_hits, &mut [0u8; 20]),
                ")",
            ],
        );
    }
    let _ = stack.close(now, &mut sink, TLS_DOMAIN, fd);
    session.close(out);
}
