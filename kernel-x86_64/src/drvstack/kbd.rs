//! The PS/2 keyboard decoder (Phase 4, item 11's completion slice):
//! i8042 scancodes → bytes into the TTY ring, the same
//! console-in the serial RX feeds.
//!
//! **The measured delivery shape:** this QEMU build delivers
//! through the controller's TRANSLATION path (legacy found live:
//! with translation off, the injected key never reaches the output
//! buffer), so the byte stream is SET-1-shaped make/break pairs.
//! The decoder is honest about that: set-1 tables, documented, not
//! a set-2 assumption the machine does not honor.
//!
//! **The decode policy:** make codes map to ASCII (letters, digits,
//! punctuation, Enter/Backspace/Tab, space); break codes (make |
//! 0x80) are consumed silently; the 0xE0 extended prefix (arrows,
//! keypad enter, etc.) consumes its follow-on byte and produces
//! nothing — the session has no cursor motion to serve, and a
//! dropped prefix would corrupt the NEXT key. Shift is tracked
//! (both keys) and picks the shifted table. Ctrl/Alt/locks/F-keys
//! are state we do not act on — decoded as None, never garbage.
//!
//! **Context:** `feed` is pure (host-tested); `irq_bottom_half` is
//! the target half — it runs INSIDE the broker's deliver() (after
//! the EOI, the tty.rs doctrine: single CPU, IF=0, the ring is
//! IRQ-safe by construction). `push` to the ring never blocks and
//! never faults; a full ring drops with the honest counter.

// Host-test builds compile this module without the port half.
#![cfg_attr(test, allow(unused_imports, dead_code))]

use core::sync::atomic::{AtomicBool, Ordering};

/// The extended (0xE0) prefix is pending: the NEXT byte is its
/// follow-on (make or break of an extended key) and produces no
/// output.
static EXT: AtomicBool = AtomicBool::new(false);
/// Either shift key is held (the shifted table is in force).
static SHIFT: AtomicBool = AtomicBool::new(false);

/// Reset the decoder state (the host tests' seam; production never
/// resets — boot starts clean).
#[cfg_attr(not(test), allow(dead_code))]
pub fn reset() {
    EXT.store(false, Ordering::Relaxed);
    SHIFT.store(false, Ordering::Relaxed);
}

/// The unshifted set-1 make table (the translation path's shape).
fn plain(make: u8) -> Option<u8> {
    Some(match make {
        // The digit row.
        0x02..=0x0B => b"1234567890"[(make - 0x02) as usize],
        0x0C => b'-',
        0x0D => b'=',
        0x0E => 0x08, // Backspace
        0x0F => b'\t',
        // QWERTY row 1.
        0x10..=0x19 => b"qwertyuiop"[(make - 0x10) as usize],
        0x1A => b'[',
        0x1B => b']',
        0x1C => b'\n',
        // HOME row: 'a' is 0x1E — the famous set-1 make code (this is
        // the TRANSLATED stream the i8042 delivers on this build).
        0x1E..=0x26 => b"asdfghjkl"[(make - 0x1E) as usize],
        0x27 => b';',
        0x28 => b'\'',
        0x29 => b'`',
        // The backslash sits between the shifts.
        0x2B => b'\\',
        // BOTTOM row.
        0x2C..=0x32 => b"zxcvbnm"[(make - 0x2C) as usize],
        0x33 => b',',
        0x34 => b'.',
        0x35 => b'/',
        // Keypad digits (the Num-Lock shape): digits and the enter.
        0x47 => b'7',
        0x48 => b'8',
        0x49 => b'9',
        0x4A => b'-',
        0x4B => b'4',
        0x4C => b'5',
        0x4D => b'6',
        0x4E => b'+',
        0x4F => b'1',
        0x50 => b'2',
        0x51 => b'3',
        0x52 => b'0',
        0x53 => b'.',
        // The space bar.
        0x39 => b' ',
        // State keys, locks and F-keys: decoded, deliberately inert.
        0x1D | 0x38 | 0x3A | 0x45 | 0x46 | 0x36 => return None,
        0x3B..=0x44 | 0x57 | 0x58 => return None, // F1..F10, F11, F12
        0x37 => return None,                      // keypad *
        // Anything else ( Pause's odd sequences, 0x56 on
        // international layouts): None, never garbage.
        _ => return None,
    })
}

/// The shifted set-1 make table.
fn shifted(make: u8) -> Option<u8> {
    Some(match make {
        0x02..=0x0B => b"!@#$%^&*()"[(make - 0x02) as usize],
        0x0C => b'_',
        0x0D => b'+',
        0x10..=0x19 => b"QWERTYUIOP"[(make - 0x10) as usize],
        0x1A => b'{',
        0x1B => b'}',
        0x1E..=0x26 => b"ASDFGHJKL"[(make - 0x1E) as usize],
        0x27 => b':',
        0x28 => b'"',
        0x29 => b'~',
        0x2B => b'|',
        0x2C..=0x32 => b"ZXCVBNM"[(make - 0x2C) as usize],
        0x33 => b'<',
        0x34 => b'>',
        0x35 => b'?',
        0x39 => b' ',
        _ => return plain(make), // keys with no shifted shape behave plain
    })
}

/// Feed one scancode. Returns the decoded byte, or None (break
/// codes, prefixes, state keys — consumed, never garbage).
pub fn feed(sc: u8) -> Option<u8> {
    // The extended prefix's follow-on: swallow (arrows, keypad
    // enter, etc. — decoded as nothing, the session has no cursor
    // motion; a DROPPED prefix would corrupt the next key).
    if EXT.load(Ordering::Relaxed) {
        EXT.store(false, Ordering::Relaxed);
        return None;
    }
    match sc {
        0xE0 => {
            EXT.store(true, Ordering::Relaxed);
            None
        }
        // 0xE1 introduces Pause's two follow-on bytes — both are
        // ordinary-looking codes, so without tracking we would decode
        // garbage. Swallow the prefix; the follow-ons (0x1D-shaped)
        // land in the None arms anyway (documented, measured shapes).
        0xE1 => None,
        // The shift presses: 0x2A (left), 0x36 (right).
        0x2A | 0x36 => {
            SHIFT.store(true, Ordering::Relaxed);
            None
        }
        // The shift breaks: 0xAA (left), 0xB6 (right).
        0xAA | 0xB6 => {
            SHIFT.store(false, Ordering::Relaxed);
            None
        }
        0x80..=0xFF => None, // any other break: consumed silently
        _ => {
            if SHIFT.load(Ordering::Relaxed) {
                shifted(sc)
            } else {
                plain(sc)
            }
        }
    }
}

/// The target half: drain the 8042's output buffer (bounded — the
/// controller's 16-byte queue plus slack), decode, and push every
/// decoded byte into the TTY ring. Runs inside `irq::deliver` after
/// the EOI. Returns the bytes pushed.
#[cfg(not(test))]
pub(crate) fn irq_bottom_half() -> usize {
    let mut pushed = 0usize;
    let mut spins = 0u64;
    while crate::hw::inb(0x64) & 1 != 0 && spins < 64 {
        let sc = crate::hw::inb(0x60);
        if let Some(b) = feed(sc) {
            if crate::tty::push(b) {
                pushed += 1;
            }
        }
        spins += 1;
    }
    pushed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plain_table_is_the_set1_translation_shape() {
        reset();
        // The digit row.
        assert_eq!(feed(0x02), Some(b'1'));
        assert_eq!(feed(0x0B), Some(b'0'));
        assert_eq!(feed(0x0C), Some(b'-'));
        // The QWERTY rows.
        assert_eq!(feed(0x10), Some(b'q'));
        assert_eq!(feed(0x19), Some(b'p'));
        // 'a' is 0x1E — THE famous set-1 make code, and the exact
        // byte the QEMU lane's translated delivery carries (the
        // round-trip marker's 0x1e).
        assert_eq!(feed(0x1E), Some(b'a'));
        assert_eq!(feed(0x26), Some(b'l'));
        assert_eq!(feed(0x2C), Some(b'z'));
        assert_eq!(feed(0x32), Some(b'm'));
        // The punctuation and the space.
        assert_eq!(feed(0x27), Some(b';'));
        assert_eq!(feed(0x28), Some(b'\''));
        assert_eq!(feed(0x29), Some(b'`'));
        assert_eq!(feed(0x2B), Some(b'\\'));
        assert_eq!(feed(0x33), Some(b','));
        assert_eq!(feed(0x35), Some(b'/'));
        assert_eq!(feed(0x39), Some(b' '));
        // The control keys the session consumes.
        assert_eq!(feed(0x1C), Some(b'\n'));
        assert_eq!(feed(0x0E), Some(0x08));
        assert_eq!(feed(0x0F), Some(b'\t'));
        // The keypad's Num-Lock shape.
        assert_eq!(feed(0x47), Some(b'7'));
        assert_eq!(feed(0x53), Some(b'.'));
    }

    #[test]
    fn breaks_and_prefixes_consume_silently() {
        reset();
        // A key's make/break pair yields exactly one byte — the lane's
        // QMP key: 'a' = 0x1E/0x9E.
        assert_eq!(feed(0x1E), Some(b'a'));
        assert_eq!(feed(0x9E), None); // its break
                                      // The extended prefix swallows its follow-on.
        assert_eq!(feed(0xE0), None);
        assert_eq!(feed(0x48), None, "the arrow's follow-on is consumed");
        assert_eq!(feed(0xE0), None);
        assert_eq!(feed(0x48 | 0x80), None, "an extended break too");
        // A prefix never leaks into the next key.
        assert_eq!(feed(0xE0), None);
        assert_eq!(feed(0x1C), None, "the keypad-enter follow-on");
        assert_eq!(feed(0x1E), Some(b'a'), "the next real key decodes clean");
    }

    #[test]
    fn shift_picks_the_shifted_table_and_latches_per_pair() {
        reset();
        assert_eq!(feed(0x2A), None, "left shift press");
        assert_eq!(feed(0x1E), Some(b'A'));
        assert_eq!(feed(0x02), Some(b'!'));
        assert_eq!(feed(0x27), Some(b':'));
        assert_eq!(feed(0x35), Some(b'?'));
        assert_eq!(feed(0x2B), Some(b'|'));
        // The break clears it — either shift key's break.
        assert_eq!(feed(0xB6), None, "right shift break clears");
        assert_eq!(feed(0x1E), Some(b'a'));
        // The right shift key works the same way.
        assert_eq!(feed(0x36), None);
        assert_eq!(feed(0x02), Some(b'!'));
        assert_eq!(feed(0xAA), None);
        assert_eq!(feed(0x02), Some(b'1'));
    }

    #[test]
    fn state_keys_locks_and_function_keys_are_inert() {
        reset();
        for sc in [0x1Du8, 0x38, 0x3A, 0x45, 0x46, 0x3B, 0x44, 0x57, 0x58, 0x37] {
            assert_eq!(feed(sc), None, "state/lock/F key {sc:#x} is inert");
        }
        // And their breaks.
        for sc in [0x9Du8, 0xB8, 0xBA, 0xC5, 0xC6] {
            assert_eq!(feed(sc), None);
        }
        // Unknown codes are None, never garbage.
        assert_eq!(feed(0x00), None);
        assert_eq!(feed(0x54), None);
        assert_eq!(feed(0xE1), None);
    }

    #[test]
    fn a_typing_burst_decodes_exactly_the_typed_line() {
        reset();
        // "hi\n" with the pairs: h=0x23 i=0x17 enter=0x1C.
        let mut out = Vec::new();
        for sc in [0x23u8, 0xA3, 0x17, 0x97, 0x1C, 0x9C] {
            if let Some(b) = feed(sc) {
                out.push(b);
            }
        }
        assert_eq!(out, b"hi\n");
        // A shifted burst: "H!" — H=shift+0x23, !=shift+0x02.
        let mut out = Vec::new();
        for sc in [0x2Au8, 0x23, 0xA3, 0xAA, 0x2A, 0x02, 0x82, 0xAA] {
            if let Some(b) = feed(sc) {
                out.push(b);
            }
        }
        assert_eq!(out, b"H!");
    }
}
