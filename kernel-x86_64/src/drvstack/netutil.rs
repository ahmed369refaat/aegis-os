//! Shared network-frame builders (big-endian stores + DHCP DISCOVER).

// Host-test builds (round 5, Phase B) compile this module WITHOUT its
// boot-only step functions, so their imports and helpers look unused
// there — they are used by the boot build. The host tests drive the
// pure logic that stays.
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

/// Byte-granular big-endian stores for the hand-built packet.
pub(crate) fn put8(pa: u64, v: u8) {
    crate::virtio::write_u8_pa(pa, v);
}

pub(crate) fn put16be(pa: u64, v: u16) {
    put8(pa, (v >> 8) as u8);
    put8(pa + 1, (v & 0xFF) as u8);
}

pub(crate) fn put32be(pa: u64, v: u32) {
    put16be(pa, (v >> 16) as u16);
    put16be(pa + 2, (v & 0xFFFF) as u16);
}

/// Build the DHCP DISCOVER at `p` (the raw Ethernet frame — the
/// e1000 path has no virtio header). Mirrors net_step's builder;
/// factor shared once the virtio-net slice stabilizes.
pub(crate) fn build_dhcp_discover_at(p: u64, mac: [u8; 6]) {
    for i in 0..320u64 {
        put8(p + i, 0);
    }
    // Ethernet: broadcast, our MAC, ethertype 0x0800.
    for i in 0..6u64 {
        put8(p + i, 0xFF);
        put8(p + 6 + i, mac[i as usize]);
    }
    put8(p + 12, 0x08);
    put8(p + 13, 0x00);
    // IPv4: total 276, TTL 64, proto 17, 0.0.0.0 → 255.255.255.255.
    let ip = p + 14;
    put8(ip, 0x45);
    put16be(ip + 2, 276);
    put16be(ip + 4, 0x0001);
    put8(ip + 8, 64);
    put8(ip + 9, 17);
    for i in 0..4u64 {
        put8(ip + 12 + i, 0);
        put8(ip + 16 + i, 0xFF);
    }
    put16be(ip + 10, crate::virtio::ip_checksum(ip, 20));
    // UDP: 68 → 67, length 256, checksum 0 (legal on IPv4).
    let udp = p + 34;
    put16be(udp, 68);
    put16be(udp + 2, 67);
    put16be(udp + 4, 256);
    // DHCP: BOOTREQUEST, xid 0xa6515151, broadcast flag, chaddr=MAC.
    let d = p + 42;
    put8(d, 1);
    put8(d + 1, 1);
    put8(d + 2, 6);
    put32be(d + 4, 0xA651_5151);
    put16be(d + 10, 0x8000);
    for i in 0..6u64 {
        put8(d + 28 + i, mac[i as usize]);
    }
    // Magic cookie + options 53 (DISCOVER), 61 (client-id), 255.
    let c = d + 236;
    put8(c, 63);
    put8(c + 1, 82);
    put8(c + 2, 83);
    put8(c + 3, 63);
    put8(c + 4, 53);
    put8(c + 5, 1);
    put8(c + 6, 1);
    put8(c + 7, 61);
    put8(c + 8, 7);
    put8(c + 9, 1);
    for i in 0..6u64 {
        put8(c + 10 + i, mac[i as usize]);
    }
    put8(c + 16, 255);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drvstack::testharness::{FakePhys, XorShift};

    fn u8_at(p: u64, off: u64) -> u8 {
        crate::virtio::read_u8_pa(p + off)
    }

    #[test]
    fn dhcp_discover_builds_a_verifiable_frame() {
        let phys = FakePhys::new(1);
        let p = phys.pa(0);
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        build_dhcp_discover_at(p, mac);
        // Ethernet: broadcast + our MAC + IPv4 ethertype
        for i in 0..6 {
            assert_eq!(u8_at(p, i), 0xFF);
            assert_eq!(u8_at(p, 6 + i), mac[i as usize]);
        }
        assert_eq!(u8_at(p, 12), 0x08);
        assert_eq!(u8_at(p, 13), 0x00);
        // IPv4: v4 hl 20, total 276, proto 17 (UDP), 0.0.0.0 -> broadcast
        assert_eq!(u8_at(p, 14), 0x45);
        assert_eq!(crate::virtio::read_u16_pa(p + 16), 276u16.rotate_right(8));
        assert_eq!(u8_at(p, 23), 17);
        // the IP header checksum VERIFIES over the built packet
        assert_eq!(
            crate::virtio::ip_checksum(p + 14, 20),
            0,
            "the stored checksum makes the header sum to zero"
        );
        // UDP: 68 -> 67
        assert_eq!(crate::virtio::read_u16_pa(p + 34), (68u16 << 8));
        // DHCP: op/hlen, xid, flags, chaddr, magic cookie, option 53 = DISCOVER
        assert_eq!(u8_at(p, 42), 1, "op = BOOTREQUEST");
        assert_eq!(u8_at(p, 43), 1, "htype = Ethernet");
        assert_eq!(u8_at(p, 44), 6, "hlen = 6-byte MAC");
        // xid 0xa6515151, stored big-endian at bytes 46-49
        assert_eq!(u8_at(p, 46), 0xA6);
        assert_eq!(u8_at(p, 47), 0x51);
        assert_eq!(u8_at(p, 48), 0x51);
        assert_eq!(u8_at(p, 49), 0x51);
        for i in 0..6 {
            assert_eq!(u8_at(p, 42 + 28 + i), mac[i as usize]);
        }
        let c = 42 + 236;
        assert_eq!(u8_at(p, c), 63);
        assert_eq!(u8_at(p, c + 1), 82);
        assert_eq!(u8_at(p, c + 2), 83);
        assert_eq!(u8_at(p, c + 3), 63, "magic cookie 0x63825363");
        assert_eq!(u8_at(p, c + 4), 53);
        assert_eq!(u8_at(p, c + 6), 1, "DHCP message type = DISCOVER");
        assert_eq!(u8_at(p, c + 16), 255, "option terminator");
    }

    /// Every MAC the device could report still builds a checksum-valid
    /// frame — no panic, no unbalanced header.
    #[test]
    fn dhcp_discover_fuzz_over_hostile_macs() {
        let phys = FakePhys::new(1);
        let p = phys.pa(0);
        let mut rng = XorShift(0xD4C9);
        for _ in 0..1000 {
            let mut mac = [0u8; 6];
            for (i, b) in mac.iter_mut().enumerate() {
                *b = (rng.next() >> (i as u64 * 8)) as u8;
            }
            build_dhcp_discover_at(p, mac);
            assert_eq!(crate::virtio::ip_checksum(p + 14, 20), 0);
            // the chaddr carries the MAC whatever it contains
            for (i, &m) in mac.iter().enumerate() {
                assert_eq!(u8_at(p, 42 + 28 + i as u64), m);
            }
        }
    }
}
