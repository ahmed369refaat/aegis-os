//! The text console (Phase 4, item 13's second slice): an 80x30
//! double-buffered text plane on the VBE linear framebuffer.
//!
//! **What is double-buffered, exactly:** the TEXT plane. The shadow
//! grid (`CELLS`) is the authoritative back buffer — every write
//! lands there first, and every blit reads it, never the other way —
//! so a scroll or a mid-line repaint can never show a torn half-
//! updated screen. A full 640x480x32 pixel back buffer (1.2 MiB) was
//! deliberately NOT taken: the kernel's frame budget is 64 MiB of
//! pool frames with real owners, and a pixel copy would cost one
//! full repaint per scroll (~307k MMIO writes) — the text-shadow
//! design repaints only the DIRTY CELLS (128 writes per character)
//! and a full repaint only on scroll. The choice is recorded here,
//! not made silently.
//!
//! **What the console mirrors:** the USER's output, not the kernel
//! log. `sys_write`'s console arm calls `write_byte` per byte (the
//! shell session and any ring-3 stdout); the kernel's own boot log
//! stays serial-only — mirroring it would add hundreds of scrolls to
//! every boot, and the console is the user's screen, not a second
//! copy of the log.
//!
//! **The status row:** row 0 is the console's permanent header —
//! written once at init, never scrolled, never touched by the body's
//! cursor. It is exactly what a real terminal's status line is, AND
//! the deterministic pixel-check target: whatever the session writes
//! (and however much it scrolls), row 0 still spells the banner when
//! the lane's QMP screendump fires — no race between the camera and
//! the output stream (found in review: a banner IN the body scrolled
//! away before the first capture).
//!
//! **Context discipline:** writers are CPL0 with IF=0 (syscall and
//! boot paths — single CPU, no interleaving exists); the IRQ bottom
//! halves never write the console. The state is atomics anyway (the
//! tty.rs doctrine: the memory model stays honest without one line
//! of unsafe — this module lives outside the allowlist).

// Host-test builds compile this module without the blit half; the
// text-plane logic (the tests' subject) stays.
#![cfg_attr(test, allow(unused_imports, unused_mut, dead_code))]

use core::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};

/// Columns: 640 px / 8-px cells.
pub const COLS: usize = 80;
/// Rows: 480 px / 16-px cells (8-px glyphs, rows doubled for
/// readability at 1x scale).
pub const ROWS: usize = 30;

/// The shadow text plane: the back buffer. One byte per cell (the
/// ASCII code); the attribute (ink/background) is a plane-wide pair,
/// changed only by `set_colors` (documented, never mid-blit).
static CELLS: [AtomicU8; COLS * ROWS] = [const { AtomicU8::new(b' ') }; COLS * ROWS];
/// The framebuffer base — 0 means "not initialized": every write is a
/// guarded no-op until `init` names the plane.
static FB: AtomicU64 = AtomicU64::new(0);
/// The write cursor (row, col) — where the next byte lands.
static ROW: AtomicU8 = AtomicU8::new(0);
static COL: AtomicU8 = AtomicU8::new(0);
/// The cell currently wearing the cursor block (row*COLS+col, or
/// COLS*ROWS = none) — erased by repainting that cell's glyph before
/// the block moves.
static CURSOR_AT: AtomicUsize = AtomicUsize::new(COLS * ROWS);
/// Cells written since init (the honest activity counter the boot
/// marker prints — the session-mirror proof).
static WRITTEN: AtomicU64 = AtomicU64::new(0);
/// Scrolls performed since init.
static SCROLLS: AtomicU64 = AtomicU64::new(0);

/// Ink: light gray.
const INK: u32 = 0xE8_E8_E8;
/// Background: dark navy.
const BG: u32 = 0x10_10_20;

/// The 8x8 bitmap font, ASCII 0x20..=0x7E (95 glyphs, one per code —
/// a table row is [u8; 8], MSB = leftmost pixel, 6-px-wide strokes
/// with a 1-px gap each side). Hand-drawn for this kernel (the
/// five-glyph AEGIS logo font of the pattern slice, generalized).
#[rustfmt::skip]
static FONT: [[u8; 8]; 95] = [
    // 0x20 ' '
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    // 0x21 '!'
    [0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18, 0x00],
    // 0x22 '"'
    [0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
    // 0x23 '#'
    [0x66, 0x66, 0xFF, 0x66, 0xFF, 0x66, 0x66, 0x00],
    // 0x24 '$'
    [0x18, 0x3E, 0x60, 0x3C, 0x06, 0x7C, 0x18, 0x00],
    // 0x25 '%'
    [0x62, 0x66, 0x0C, 0x18, 0x30, 0x66, 0x46, 0x00],
    // 0x26 '&'
    [0x3C, 0x66, 0x3C, 0x38, 0x67, 0x66, 0x3F, 0x00],
    // 0x27 '''
    [0x06, 0x0C, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00],
    // 0x28 '('
    [0x0C, 0x18, 0x30, 0x30, 0x30, 0x18, 0x0C, 0x00],
    // 0x29 ')'
    [0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x18, 0x30, 0x00],
    // 0x2A '*'
    [0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00, 0x00],
    // 0x2B '+'
    [0x00, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x00, 0x00],
    // 0x2C ','
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x30],
    // 0x2D '-'
    [0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00],
    // 0x2E '.'
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00],
    // 0x2F '/'
    [0x00, 0x03, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x00],
    // 0x30 '0'
    [0x1C, 0x36, 0x63, 0x6B, 0x63, 0x36, 0x1C, 0x00],
    // 0x31 '1'
    [0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00],
    // 0x32 '2'
    [0x3C, 0x66, 0x06, 0x0C, 0x30, 0x60, 0x7F, 0x00],
    // 0x33 '3'
    [0x3C, 0x66, 0x06, 0x1C, 0x06, 0x66, 0x3C, 0x00],
    // 0x34 '4'
    [0x06, 0x0E, 0x1E, 0x66, 0x7F, 0x06, 0x06, 0x00],
    // 0x35 '5'
    [0x7F, 0x60, 0x7C, 0x06, 0x06, 0x66, 0x3C, 0x00],
    // 0x36 '6'
    [0x3C, 0x66, 0x60, 0x7C, 0x66, 0x66, 0x3C, 0x00],
    // 0x37 '7'
    [0x7F, 0x66, 0x0C, 0x18, 0x18, 0x18, 0x18, 0x00],
    // 0x38 '8'
    [0x3C, 0x66, 0x66, 0x3C, 0x66, 0x66, 0x3C, 0x00],
    // 0x39 '9'
    [0x3C, 0x66, 0x66, 0x3E, 0x06, 0x66, 0x3C, 0x00],
    // 0x3A ':'
    [0x00, 0x00, 0x18, 0x00, 0x00, 0x18, 0x00, 0x00],
    // 0x3B ';'
    [0x00, 0x00, 0x18, 0x00, 0x00, 0x18, 0x18, 0x30],
    // 0x3C '<'
    [0x0E, 0x18, 0x30, 0x60, 0x30, 0x18, 0x0E, 0x00],
    // 0x3D '='
    [0x00, 0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00, 0x00],
    // 0x3E '>'
    [0x70, 0x18, 0x0C, 0x06, 0x0C, 0x18, 0x70, 0x00],
    // 0x3F '?'
    [0x3C, 0x66, 0x06, 0x0C, 0x18, 0x00, 0x18, 0x00],
    // 0x40 '@'
    [0x3C, 0x66, 0x6B, 0x6B, 0x6B, 0x7C, 0x3C, 0x00],
    // 0x41 'A'
    [0x0C, 0x1E, 0x33, 0x33, 0x3F, 0x33, 0x33, 0x00],
    // 0x42 'B'
    [0x3F, 0x66, 0x66, 0x3E, 0x66, 0x66, 0x3F, 0x00],
    // 0x43 'C'
    [0x3C, 0x66, 0x60, 0x60, 0x60, 0x66, 0x3C, 0x00],
    // 0x44 'D'
    [0x38, 0x6C, 0x66, 0x66, 0x66, 0x6C, 0x38, 0x00],
    // 0x45 'E'
    [0x7F, 0x60, 0x60, 0x7E, 0x60, 0x60, 0x7F, 0x00],
    // 0x46 'F'
    [0x7F, 0x60, 0x60, 0x7E, 0x60, 0x60, 0x60, 0x00],
    // 0x47 'G'
    [0x3C, 0x66, 0x60, 0x6F, 0x66, 0x66, 0x3C, 0x00],
    // 0x48 'H'
    [0x33, 0x33, 0x33, 0x3F, 0x33, 0x33, 0x33, 0x00],
    // 0x49 'I'
    [0x1E, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x1E, 0x00],
    // 0x4A 'J'
    [0x07, 0x06, 0x06, 0x06, 0x06, 0x66, 0x3C, 0x00],
    // 0x4B 'K'
    [0x66, 0x6C, 0x78, 0x70, 0x78, 0x6C, 0x66, 0x00],
    // 0x4C 'L'
    [0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7F, 0x00],
    // 0x4D 'M'
    [0x63, 0x77, 0x7F, 0x7F, 0x6B, 0x63, 0x63, 0x00],
    // 0x4E 'N'
    [0x63, 0x67, 0x6F, 0x7B, 0x73, 0x63, 0x63, 0x00],
    // 0x4F 'O'
    [0x1C, 0x36, 0x63, 0x63, 0x63, 0x36, 0x1C, 0x00],
    // 0x50 'P'
    [0x3F, 0x66, 0x66, 0x3E, 0x60, 0x60, 0x60, 0x00],
    // 0x51 'Q'
    [0x1E, 0x36, 0x36, 0x3E, 0x6E, 0x66, 0x3B, 0x00],
    // 0x52 'R'
    [0x3F, 0x66, 0x66, 0x3E, 0x6C, 0x66, 0x63, 0x00],
    // 0x53 'S'
    [0x3C, 0x66, 0x60, 0x3C, 0x06, 0x66, 0x3C, 0x00],
    // 0x54 'T'
    [0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00],
    // 0x55 'U'
    [0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x3F, 0x00],
    // 0x56 'V'
    [0x33, 0x33, 0x33, 0x33, 0x33, 0x1E, 0x0C, 0x00],
    // 0x57 'W'
    [0x63, 0x63, 0x63, 0x6B, 0x7F, 0x77, 0x63, 0x00],
    // 0x58 'X'
    [0x63, 0x63, 0x36, 0x1C, 0x1C, 0x36, 0x63, 0x00],
    // 0x59 'Y'
    [0x33, 0x33, 0x33, 0x1E, 0x0C, 0x0C, 0x0C, 0x00],
    // 0x5A 'Z'
    [0x7F, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7F, 0x00],
    // 0x5B '['
    [0x3C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3C, 0x00],
    // 0x5C '\'
    [0x00, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x03, 0x00],
    // 0x5D ']'
    [0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C, 0x00],
    // 0x5E '^'
    [0x18, 0x3C, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
    // 0x5F '_'
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF],
    // 0x60 '`'
    [0x30, 0x18, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00],
    // 0x61 'a'
    [0x00, 0x00, 0x3C, 0x06, 0x3E, 0x66, 0x3E, 0x00],
    // 0x62 'b'
    [0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x00],
    // 0x63 'c'
    [0x00, 0x00, 0x3C, 0x60, 0x60, 0x60, 0x3C, 0x00],
    // 0x64 'd'
    [0x06, 0x06, 0x3E, 0x66, 0x66, 0x66, 0x3E, 0x00],
    // 0x65 'e'
    [0x00, 0x00, 0x3C, 0x66, 0x7E, 0x60, 0x3C, 0x00],
    // 0x66 'f'
    [0x0E, 0x18, 0x3E, 0x18, 0x18, 0x18, 0x18, 0x00],
    // 0x67 'g'
    [0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x7C],
    // 0x68 'h'
    [0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00],
    // 0x69 'i'
    [0x0C, 0x00, 0x1C, 0x0C, 0x0C, 0x0C, 0x1E, 0x00],
    // 0x6A 'j'
    [0x06, 0x00, 0x06, 0x06, 0x06, 0x06, 0x66, 0x3C],
    // 0x6B 'k'
    [0x60, 0x60, 0x66, 0x6C, 0x78, 0x6C, 0x66, 0x00],
    // 0x6C 'l'
    [0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00],
    // 0x6D 'm'
    [0x00, 0x00, 0x66, 0x7F, 0x7F, 0x6B, 0x63, 0x00],
    // 0x6E 'n'
    [0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00],
    // 0x6F 'o'
    [0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x3C, 0x00],
    // 0x70 'p'
    [0x00, 0x00, 0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60],
    // 0x71 'q'
    [0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x06],
    // 0x72 'r'
    [0x00, 0x00, 0x3E, 0x66, 0x70, 0x60, 0x60, 0x00],
    // 0x73 's'
    [0x00, 0x00, 0x3E, 0x60, 0x3C, 0x06, 0x7C, 0x00],
    // 0x74 't'
    [0x18, 0x18, 0x7E, 0x18, 0x18, 0x18, 0x0E, 0x00],
    // 0x75 'u'
    [0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x3E, 0x00],
    // 0x76 'v'
    [0x00, 0x00, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00],
    // 0x77 'w'
    [0x00, 0x00, 0x63, 0x6B, 0x7F, 0x7F, 0x36, 0x00],
    // 0x78 'x'
    [0x00, 0x00, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x00],
    // 0x79 'y'
    [0x00, 0x00, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x7C],
    // 0x7A 'z'
    [0x00, 0x00, 0x7E, 0x0C, 0x18, 0x30, 0x7E, 0x00],
    // 0x7B '{'
    [0x0E, 0x18, 0x18, 0x70, 0x18, 0x18, 0x0E, 0x00],
    // 0x7C '|'
    [0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18],
    // 0x7D '}'
    [0x70, 0x18, 0x18, 0x0E, 0x18, 0x18, 0x70, 0x00],
    // 0x7E '~'
    [0x00, 0x00, 0x1C, 0x36, 0x1C, 0x00, 0x00, 0x00],
];

/// The glyph for a code, or None (out of the table — the writer's
/// problem, never a panic).
#[cfg_attr(test, allow(dead_code))]
fn glyph(code: u8) -> Option<[u8; 8]> {
    if (0x20..=0x7E).contains(&code) {
        Some(FONT[(code - 0x20) as usize])
    } else {
        None
    }
}

/// The plane's activity counters, for the boot marker: (cells
/// written, scrolls).
pub fn stats() -> (u64, u64) {
    (
        WRITTEN.load(Ordering::Relaxed),
        SCROLLS.load(Ordering::Relaxed),
    )
}

/// Whether the plane is live (the mirror gates on this — before
/// `init`, every write is a no-op, and the serial log is the only
/// console).
pub fn is_live() -> bool {
    FB.load(Ordering::Acquire) != 0
}

// ── the text-plane logic (pure, host-tested) ────────────────────────

/// The body region: rows 1..=ROWS-1 (row 0 is the status row).
pub const BODY_FIRST: usize = 1;

/// Advance the cursor one cell, scrolling when the last row fills.
/// Pure: (row, col) in, (row, col) out, scroll flag out. The cursor
/// never enters row 0 — the status row is not body text.
fn advance(row: usize, col: usize) -> (usize, usize, bool) {
    if col + 1 < COLS {
        (row, col + 1, false)
    } else if row + 1 < ROWS {
        (row + 1, 0, false)
    } else {
        (ROWS - 1, 0, true)
    }
}

/// The control-code policy (pure, host-tested): what one byte does to
/// the plane. Tab advances to the next multiple of 8; backspace moves
/// back one cell (and the caller blanks it); CR homes the column;
/// LF advances the row (and scrolls at the bottom); printable codes
/// occupy one cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Place `code` at (row, col), then advance.
    Put(u8, usize, usize),
    /// Move to (row, col) without writing.
    Move(usize, usize),
    /// The last row filled: move to (row, col) AND the plane scrolls
    /// (the caller performs the copy).
    ScrollTo(usize, usize),
}

/// One byte's effect on the cursor.
pub fn step(row: usize, col: usize, b: u8) -> Step {
    match b {
        b'\r' => Step::Move(row, 0),
        b'\n' => {
            if row + 1 < ROWS {
                Step::Move(row + 1, 0)
            } else {
                Step::ScrollTo(ROWS - 1, 0)
            }
        }
        b'\t' => {
            let next = (col + 8) & !7;
            if next < COLS {
                Step::Move(row, next)
            } else if row + 1 < ROWS {
                Step::Move(row + 1, 0)
            } else {
                Step::ScrollTo(ROWS - 1, 0)
            }
        }
        0x08 => {
            // Backspace: back one cell (at (r,0) wrap up a row; at the
            // top-left, stay).
            if col > 0 {
                Step::Move(row, col - 1)
            } else if row > 0 {
                Step::Move(row - 1, COLS - 1)
            } else {
                Step::Move(0, 0)
            }
        }
        _ => {
            // A printable byte ALWAYS occupies its cell (the eager
            // wrap in `write_byte` fires after the store — a byte is
            // never lost to the scroll). Out-of-table codes render as
            // a replacement mark, not dropped.
            Step::Put(if glyph(b).is_some() { b } else { b'?' }, row, col)
        }
    }
}

/// Scroll the BODY one row up (pure: the copy the target half
/// blits): rows 2..=ROWS-1 move to 1..=ROWS-2, the last row blanks.
/// Row 0 — the status row — is never touched: the header survives
/// every scroll (the pixel check's whole premise).
fn scroll_cells() {
    for r in BODY_FIRST..ROWS - 1 {
        for c in 0..COLS {
            let v = CELLS[(r + 1) * COLS + c].load(Ordering::Relaxed);
            CELLS[r * COLS + c].store(v, Ordering::Relaxed);
        }
    }
    for c in 0..COLS {
        CELLS[(ROWS - 1) * COLS + c].store(b' ', Ordering::Relaxed);
    }
    SCROLLS.fetch_add(1, Ordering::Relaxed);
}

// ── the write path (the target half's blit guarded, the logic above
//    exercised on the host by driving the same functions) ──────────

/// Write one byte to the plane. Before `init` this is a guarded
/// no-op. Control codes follow [`step`]; printable codes land in the
/// shadow and blit their CELL (128 pixel writes); a full scroll blits
/// the whole plane (the shadow is authoritative, so no tear).
pub fn write_byte(b: u8) {
    if !is_live() {
        return;
    }
    let row = ROW.load(Ordering::Relaxed) as usize;
    let col = COL.load(Ordering::Relaxed) as usize;
    match step(row, col, b) {
        Step::Put(code, r, c) => {
            CELLS[r * COLS + c].store(code, Ordering::Release);
            WRITTEN.fetch_add(1, Ordering::Relaxed);
            blit_cell(r, c);
            // Eager wrap: the plane's LAST cell, once filled, scrolls
            // immediately (the next byte needs a place — one rule, not
            // a lazy/eager pair). The byte itself survives in the
            // scrolled-up row: nothing is lost.
            let (nr, nc, scroll) = advance(r, c);
            if scroll {
                scroll_cells();
                blit_all();
            }
            move_cursor(nr, nc);
        }
        Step::Move(r, c) => move_cursor(r, c),
        Step::ScrollTo(r, c) => {
            scroll_cells();
            blit_all();
            move_cursor(r, c);
        }
    }
}

/// Write a whole string (the mirror's unit — one sys_write call).
pub fn write_str(s: &str) {
    for b in s.bytes() {
        write_byte(b);
    }
}

/// Move the write cursor, erasing the old cursor block by repainting
/// its cell and drawing the block at the new position.
fn move_cursor(row: usize, col: usize) {
    let old = CURSOR_AT.load(Ordering::Relaxed);
    let new = row * COLS + col;
    if old < COLS * ROWS {
        blit_cell_plain(old / COLS, old % COLS);
    }
    if new < COLS * ROWS {
        blit_cursor(new / COLS, new % COLS);
    }
    CURSOR_AT.store(new, Ordering::Relaxed);
    ROW.store(row as u8, Ordering::Relaxed);
    COL.store(col as u8, Ordering::Relaxed);
}

// ── the blit half (target-only: framebuffer MMIO writes) ────────────

#[cfg(not(test))]
fn px(x: u64, y: u64, rgb: u32) {
    let fb = FB.load(Ordering::Relaxed);
    crate::memops::write_u32(fb + (y * 640 + x) * 4, rgb);
}

#[cfg(test)]
fn px(_x: u64, _y: u64, _rgb: u32) {}

/// Blit one cell: the glyph rows doubled (8x16), ink where the bit is
/// set, background elsewhere. The cursor block (ink on the bottom two
/// glyph rows) rides separately.
fn blit_cell(row: usize, col: usize) {
    let code = CELLS[row * COLS + col].load(Ordering::Relaxed);
    let g = glyph(code).unwrap_or([0; 8]);
    let x0 = (col * 8) as u64;
    let y0 = (row * 16) as u64;
    for ry in 0..8u64 {
        let rgb = |bit: u64| -> u32 {
            if g[ry as usize] >> (7 - bit) & 1 == 1 {
                INK
            } else {
                BG
            }
        };
        for rx in 0..8u64 {
            let c = rgb(rx);
            px(x0 + rx, y0 + ry * 2, c);
            px(x0 + rx, y0 + ry * 2 + 1, c);
        }
    }
}

/// The cursor-free blit (repaint a cell that wears the block).
#[cfg_attr(test, allow(dead_code))]
fn blit_cell_plain(row: usize, col: usize) {
    blit_cell(row, col);
}

/// The cursor block: two ink rows at the cell's baseline (a classic
/// hardware-cursor underline).
#[cfg_attr(test, allow(dead_code))]
fn blit_cursor(row: usize, col: usize) {
    let x0 = (col * 8) as u64;
    let y0 = (row * 16) as u64;
    for rx in 0..8u64 {
        px(x0 + rx, y0 + 14, INK);
        px(x0 + rx, y0 + 15, INK);
    }
}

/// Full repaint from the shadow (init and scroll only — the shadow is
/// the plane's truth, so this is idempotent and tear-free).
#[cfg_attr(test, allow(dead_code))]
fn blit_all() {
    for r in 0..ROWS {
        for c in 0..COLS {
            blit_cell(r, c);
        }
    }
}

/// The status row's fixed text (pure ASCII — the em-dash-free form:
/// every cell maps to a real glyph, no replacement marks on the one
/// line the pixel check samples).
pub const STATUS_ROW_TEXT: &str = "AEGIS TEXT CONSOLE - 80X30 DOUBLE-BUFFERED PLANE";

/// The status row: written directly into row 0's cells, blitted, and
/// NEVER scrolled — the deterministic header the lane's pixel check
/// samples at any time after init.
pub fn set_status_row(s: &str) {
    for cell in CELLS.iter().take(COLS) {
        cell.store(b' ', Ordering::Relaxed);
    }
    for (c, b) in s.bytes().take(COLS).enumerate() {
        let code = if glyph(b).is_some() { b } else { b'?' };
        CELLS[c].store(code, Ordering::Release);
    }
    for c in 0..COLS {
        blit_cell(0, c);
    }
    WRITTEN.fetch_add(s.len().min(COLS) as u64, Ordering::Relaxed);
}

/// The framebuffer the NEXT `init_pending` will name (0 = none
/// pending). `gfx_step` records it the moment it validates the
/// window; the console itself arms at the END of the driver phase —
/// the pattern's QMP screendump needs the seconds in between, and a
/// console that blanks the splash before the camera fires would eat
/// the proof (found in review, before it ever raced once).
static PENDING_FB: AtomicU64 = AtomicU64::new(0);

/// Record the framebuffer to arm at the phase's end (the caller —
/// `gfx_step` — validated the window; nothing is drawn here).
pub fn set_pending_fb(fb: u64) {
    PENDING_FB.store(fb, Ordering::Relaxed);
}

/// Bring the plane up: name the framebuffer, blank the shadow, paint
/// the background, write the banner (the deterministic first lines
/// the lane's pixel check samples). Called at the END of the driver
/// phase so the splash's screendump window stays open through the
/// storage/network steps.
#[cfg(not(test))]
pub fn init_pending() -> bool {
    let fb = PENDING_FB.load(Ordering::Relaxed);
    if fb == 0 {
        return false;
    }
    FB.store(fb, Ordering::Release);
    for r in 0..ROWS {
        for c in 0..COLS {
            CELLS[r * COLS + c].store(b' ', Ordering::Relaxed);
        }
    }
    blit_all();
    set_status_row(STATUS_ROW_TEXT);
    ROW.store(BODY_FIRST as u8, Ordering::Relaxed);
    COL.store(0, Ordering::Relaxed);
    move_cursor(BODY_FIRST, 0);
    true
}

#[cfg(test)]
pub fn init_pending() -> bool {
    let fb = PENDING_FB.load(Ordering::Relaxed);
    if fb == 0 {
        return false;
    }
    FB.store(fb, Ordering::Release);
    for r in 0..ROWS {
        for c in 0..COLS {
            CELLS[r * COLS + c].store(b' ', Ordering::Relaxed);
        }
    }
    set_status_row(STATUS_ROW_TEXT);
    ROW.store(BODY_FIRST as u8, Ordering::Relaxed);
    COL.store(0, Ordering::Relaxed);
    move_cursor(BODY_FIRST, 0);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The console's state is one set of process-wide statics, so the
    /// stateful tests here are serial by necessity: cargo test runs
    /// them on parallel threads and interleaved `write_byte`s corrupt
    /// each other's counters (found live on bebefab: 3–4 of the 6
    /// failed per scheduling; single-threaded always green). One
    /// mutex, one guard per stateful test. The two pure tests (`step`,
    /// `glyph`) never touch the statics and need no guard.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take the console-plane lock; a poisoned mutex (a previous test
    /// panicked mid-flight) is recovered, not propagated.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reset the plane between tests (the shadow, the cursor, the
    /// counters — everything but FB, which the tests set themselves).
    fn reset() {
        for r in 0..ROWS {
            for c in 0..COLS {
                CELLS[r * COLS + c].store(b' ', Ordering::Relaxed);
            }
        }
        ROW.store(BODY_FIRST as u8, Ordering::Relaxed);
        COL.store(0, Ordering::Relaxed);
        CURSOR_AT.store(COLS * ROWS, Ordering::Relaxed);
        WRITTEN.store(0, Ordering::Relaxed);
        SCROLLS.store(0, Ordering::Relaxed);
    }

    #[test]
    fn the_cursor_policy_is_exactly_the_control_codes() {
        // Printable: place at the cursor, advance right.
        assert_eq!(step(0, 0, b'X'), Step::Put(b'X', 0, 0));
        assert_eq!(step(3, 40, b'!'), Step::Put(b'!', 3, 40));
        // The line's last cell: place, then wrap to the next row.
        assert_eq!(step(2, COLS - 1, b'z'), Step::Put(b'z', 2, COLS - 1));
        // LF advances the row, homes the column.
        assert_eq!(step(4, 40, b'\n'), Step::Move(5, 0));
        // LF at the bottom row: the scroll.
        assert_eq!(step(ROWS - 1, 40, b'\n'), Step::ScrollTo(ROWS - 1, 0));
        // CR homes the column only.
        assert_eq!(step(4, 40, b'\r'), Step::Move(4, 0));
        // Tab: the next multiple of 8, never past the line's end.
        assert_eq!(step(0, 0, b'\t'), Step::Move(0, 8));
        assert_eq!(step(0, 5, b'\t'), Step::Move(0, 8));
        assert_eq!(step(0, 8, b'\t'), Step::Move(0, 16));
        assert_eq!(step(0, 77, b'\t'), Step::Move(1, 0));
        assert_eq!(step(ROWS - 1, 77, b'\t'), Step::ScrollTo(ROWS - 1, 0));
        // Backspace: back one cell, wrapping up a row at the margin.
        assert_eq!(step(2, 10, 0x08), Step::Move(2, 9));
        assert_eq!(step(2, 0, 0x08), Step::Move(1, COLS - 1));
        assert_eq!(step(0, 0, 0x08), Step::Move(0, 0));
        // Out-of-table codes become the replacement mark, never drop.
        assert_eq!(step(0, 0, 0x1B), Step::Put(b'?', 0, 0));
        assert_eq!(step(0, 0, 0xC3), Step::Put(b'?', 0, 0));
    }

    #[test]
    fn writing_scrolls_exactly_when_the_last_cell_fills_and_the_status_row_survives() {
        let _serial = serial();
        reset();
        set_status_row("STATUS");
        FB.store(0x1000, Ordering::Relaxed); // live plane, host blit = no-op
                                             // Fill the whole BODY (rows 1..=29) from the body cursor's
                                             // start. The EAGER wrap rule: the last cell's fill scrolls
                                             // right there (the next byte already needs the place).
        let body_cells = (ROWS - BODY_FIRST) * COLS;
        for i in 0..body_cells {
            write_byte(b'A' + (i % 26) as u8);
        }
        assert_eq!(WRITTEN.load(Ordering::Relaxed), body_cells as u64 + 6);
        assert_eq!(
            SCROLLS.load(Ordering::Relaxed),
            1,
            "the last cell's fill scrolled once"
        );
        // THE STATUS ROW SURVIVED the scroll — the pixel check's whole
        // premise.
        for (c, want) in "STATUS".bytes().enumerate() {
            assert_eq!(CELLS[c].load(Ordering::Relaxed), want, "status row col {c}");
        }
        assert_eq!(CELLS[6].load(Ordering::Relaxed), b' ');
        // After the scroll: the cursor sits at the last row's start.
        assert_eq!(ROW.load(Ordering::Relaxed) as usize, ROWS - 1);
        assert_eq!(COL.load(Ordering::Relaxed) as usize, 0);
        // The scroll moved the old last body line (which ended the
        // fill) up one row: row ROWS-2 holds its first byte.
        assert_eq!(
            CELLS[(ROWS - 2) * COLS].load(Ordering::Relaxed),
            b'A' + (((body_cells - COLS) % 26) as u8),
            "row copy is exact"
        );
        // The last row is blank after the scroll; the next byte lands
        // there WITHOUT a second scroll.
        assert_eq!(CELLS[(ROWS - 1) * COLS].load(Ordering::Relaxed), b' ');
        write_byte(b'Z');
        assert_eq!(SCROLLS.load(Ordering::Relaxed), 1, "no scroll was needed");
        assert_eq!(CELLS[(ROWS - 1) * COLS].load(Ordering::Relaxed), b'Z');
        assert_eq!(COL.load(Ordering::Relaxed) as usize, 1);
        FB.store(0, Ordering::Relaxed);
    }

    #[test]
    fn newline_and_tab_at_the_edges_behave() {
        let _serial = serial();
        reset();
        FB.store(0x1000, Ordering::Relaxed);
        // A newline per body row, then one more: 29 newlines total,
        // one scroll (the 29th fires at the bottom row).
        for _r in 0..(ROWS - BODY_FIRST) {
            write_byte(b'\n');
        }
        assert_eq!(SCROLLS.load(Ordering::Relaxed), 1);
        assert_eq!(COL.load(Ordering::Relaxed) as usize, 0);
        // Tab past the line's end moves rows, not columns.
        COL.store(76, Ordering::Relaxed);
        write_byte(b'\t');
        assert_eq!(ROW.load(Ordering::Relaxed) as usize, ROWS - 1);
        assert_eq!(COL.load(Ordering::Relaxed) as usize, 0);
        FB.store(0, Ordering::Relaxed);
    }

    #[test]
    fn the_status_row_write_never_moves_the_body_cursor() {
        let _serial = serial();
        reset();
        FB.store(0x1000, Ordering::Relaxed);
        write_byte(b'x');
        let (r, c) = (
            ROW.load(Ordering::Relaxed) as usize,
            COL.load(Ordering::Relaxed) as usize,
        );
        set_status_row("HEADER");
        assert_eq!(
            (
                ROW.load(Ordering::Relaxed) as usize,
                COL.load(Ordering::Relaxed) as usize
            ),
            (r, c),
            "the body cursor is untouched"
        );
        assert_eq!(CELLS[0].load(Ordering::Relaxed), b'H');
        assert_eq!(CELLS[BODY_FIRST * COLS].load(Ordering::Relaxed), b'x');
        // A body line longer than the status text overflows DOWN, never
        // into row 0.
        let long: String = std::iter::repeat_n('y', 200).collect();
        write_str(&long);
        assert_eq!(
            CELLS[0].load(Ordering::Relaxed),
            b'H',
            "row 0 is still the header"
        );
        assert_eq!(CELLS[BODY_FIRST * COLS].load(Ordering::Relaxed), b'x');
        FB.store(0, Ordering::Relaxed);
    }

    #[test]
    fn the_font_covers_every_printable_ascii_and_is_inked() {
        // 95 glyphs, one per code 0x20..=0x7E — every printable maps,
        // and every non-space glyph has at least one ink bit (a blank
        // glyph for a visible code would be a silent drop).
        for code in 0x20..=0x7Eu32 {
            let g = glyph(code as u8).expect("every printable code has a glyph");
            if code != 0x20 {
                assert!(
                    g.iter().any(|&r| r != 0),
                    "glyph {:#x} ({}) is blank",
                    code,
                    code as u8 as char
                );
            }
        }
        // And nothing else maps.
        assert!(glyph(0x1F).is_none());
        assert!(glyph(0x7F).is_none());
    }

    #[test]
    fn a_dead_plane_swallows_everything() {
        let _serial = serial();
        reset();
        FB.store(0, Ordering::Relaxed);
        write_str("nothing lands before init");
        assert_eq!(WRITTEN.load(Ordering::Relaxed), 0);
        assert_eq!(ROW.load(Ordering::Relaxed) as usize, BODY_FIRST);
        assert_eq!(COL.load(Ordering::Relaxed) as usize, 0);
    }
}
