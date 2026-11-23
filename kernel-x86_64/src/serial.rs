//! COM1 serial output (QEMU `-serial stdio`).
//!
//! Pure safe code: all port access goes through the `hw` primitives.
//! Polled mode — we wait for the transmitter to drain. Boot logging only;
//! there is no interrupt-driven console in M1.

const COM1: u16 = 0x3F8;

/// Initialize COM1: 115200 baud, 8N1, FIFO on. QEMU's serial is tolerant,
/// but a real init keeps this honest on hardware too.
pub fn init() {
    crate::hw::outb(COM1 + 1, 0x00); // disable interrupts
    crate::hw::outb(COM1 + 3, 0x80); // DLAB on
    crate::hw::outb(COM1, 0x01); // divisor low = 1 → 115200 baud
    crate::hw::outb(COM1 + 1, 0x00); // divisor high
    crate::hw::outb(COM1 + 3, 0x03); // 8 bits, no parity, 1 stop; DLAB off
                                     // FIFO enable ONLY — never the clear bits: a scripted stdin (the
                                     // shell lane) can feed the receiver before this line runs, and the
                                     // FCR clear would wipe the session's first byte (found live: the
                                     // 'e' of the first command died exactly here). The UART is fresh
                                     // from QEMU's reset — there is nothing honest to clear.
    crate::hw::outb(COM1 + 2, 0x01);
    crate::hw::outb(COM1 + 4, 0x0B); // DTR + RTS + OUT2
}

/// Write one byte, waiting for the transmitter holding register to empty.
pub fn write_byte(b: u8) {
    while crate::hw::inb(COM1 + 5) & 0x20 == 0 {
        // Transmitter holding register not empty yet: poll.
    }
    crate::hw::outb(COM1, b);
}

/// Write a byte slice verbatim.
pub fn write_bytes(bytes: &[u8]) {
    for &b in bytes {
        write_byte(b);
    }
}

/// Write a string verbatim (no newline appended — callers decide).
pub fn write_str(s: &str) {
    write_bytes(s.as_bytes());
}
