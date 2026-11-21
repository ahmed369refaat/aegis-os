//! Shared network-frame builders (big-endian stores + DHCP DISCOVER).

/// Byte-granular big-endian stores for the hand-built packet.
#[cfg(not(test))]
pub(crate) fn put8(pa: u64, v: u8) {
    crate::virtio::write_u8_pa(pa, v);
}

#[cfg(not(test))]
pub(crate) fn put16be(pa: u64, v: u16) {
    put8(pa, (v >> 8) as u8);
    put8(pa + 1, (v & 0xFF) as u8);
}

#[cfg(not(test))]
pub(crate) fn put32be(pa: u64, v: u32) {
    put16be(pa, (v >> 16) as u16);
    put16be(pa + 2, (v & 0xFFFF) as u16);
}

/// Build the DHCP DISCOVER at `p` (the raw Ethernet frame — the
/// e1000 path has no virtio header). Mirrors net_step's builder;
/// factor shared once the virtio-net slice stabilizes.
#[cfg(not(test))]
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
