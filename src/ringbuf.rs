//! Fixed-capacity SPSC ring buffer for telemetry.
//!
//! The fast path (`push`) never blocks and never panics: when the ring is
//! full the event is dropped and a saturating drop counter is bumped. Index
//! arithmetic uses power-of-two masking (`& (N-1)`) — no modulo, no division,
//! deterministic cost. This is how measurement data leaves the hot path at
//! near-zero overhead.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingError {
    /// Capacity must be a power of two and at least 1.
    InvalidCapacity,
    /// Ring full; the item was dropped and counted.
    Full,
}

pub struct RingBuffer<T: Copy + Default, const N: usize> {
    buf: [T; N],
    head: usize, // next write index
    tail: usize, // next read index
    count: usize,
    dropped: u64,
}

impl<T: Copy + Default, const N: usize> RingBuffer<T, N> {
    /// Fails unless `N` is a power of two >= 1 (index masking requirement).
    pub fn new() -> Result<Self, RingError> {
        if N == 0 || N & N.wrapping_sub(1) != 0 {
            return Err(RingError::InvalidCapacity);
        }
        Ok(RingBuffer {
            buf: [T::default(); N],
            head: 0,
            tail: 0,
            count: 0,
            dropped: 0,
        })
    }

    /// Non-blocking push. On full: drop, count, return Err.
    pub fn push(&mut self, item: T) -> Result<(), RingError> {
        if self.count == N {
            self.dropped = self.dropped.saturating_add(1);
            return Err(RingError::Full);
        }
        self.buf[self.head] = item;
        self.head = (self.head + 1) & (N - 1);
        self.count += 1;
        Ok(())
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.count == 0 {
            return None;
        }
        let item = self.buf[self.tail];
        self.tail = (self.tail + 1) & (N - 1);
        self.count -= 1;
        Some(item)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[must_use]
    pub fn is_full(&self) -> bool {
        self.count == N
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        N
    }

    /// Cumulative dropped-event count (never reset by `clear`).
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Reset contents; the drop counter is intentionally kept (audit trail).
    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }
}

impl<T: Copy + Default, const N: usize> Default for RingBuffer<T, N> {
    fn default() -> Self {
        // Callers must use `new()`; Default only for owned-init convenience
        // in contexts where capacity was already validated by the type.
        match Self::new() {
            Ok(rb) => rb,
            Err(_) => unreachable!("RingBuffer used with non-power-of-two N"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_capacity_rejected() {
        assert!(matches!(
            RingBuffer::<u8, 0>::new(),
            Err(RingError::InvalidCapacity)
        ));
    }

    #[test]
    fn non_power_of_two_capacity_rejected() {
        assert!(matches!(
            RingBuffer::<u8, 3>::new(),
            Err(RingError::InvalidCapacity)
        ));
        assert!(matches!(
            RingBuffer::<u8, 6>::new(),
            Err(RingError::InvalidCapacity)
        ));
        assert!(matches!(
            RingBuffer::<u8, 12>::new(),
            Err(RingError::InvalidCapacity)
        ));
        assert!(RingBuffer::<u8, 1>::new().is_ok());
        assert!(RingBuffer::<u8, 2>::new().is_ok());
        assert!(RingBuffer::<u8, 16>::new().is_ok());
    }

    #[test]
    fn capacity_one_lifecycle() {
        let mut rb = RingBuffer::<u32, 1>::new().unwrap();
        assert_eq!(rb.capacity(), 1);
        assert!(rb.is_empty());
        rb.push(42).unwrap();
        assert!(rb.is_full());
        assert_eq!(rb.push(43), Err(RingError::Full));
        assert_eq!(rb.dropped(), 1);
        assert_eq!(rb.pop(), Some(42));
        assert!(rb.is_empty());
        assert_eq!(rb.pop(), None);
        rb.push(44).unwrap();
        assert_eq!(rb.pop(), Some(44));
    }

    #[test]
    fn fifo_order_preserved() {
        let mut rb = RingBuffer::<u32, 8>::new().unwrap();
        for i in 0..8u32 {
            rb.push(i).unwrap();
        }
        assert!(rb.is_full());
        for i in 0..8u32 {
            assert_eq!(rb.pop(), Some(i));
        }
        assert_eq!(rb.pop(), None);
    }

    #[test]
    fn overflow_push_counts_drops_exactly() {
        let mut rb = RingBuffer::<u32, 8>::new().unwrap();
        for i in 0..8u32 {
            rb.push(i).unwrap();
        }
        // 100 total pushes, 8 slots: the last 92 are dropped.
        for i in 8..100u32 {
            assert_eq!(rb.push(i), Err(RingError::Full));
        }
        assert_eq!(rb.dropped(), 92);
        // Original contents untouched.
        assert_eq!(rb.pop(), Some(0));
    }

    #[test]
    fn wraparound_keeps_order_across_many_cycles() {
        let mut rb = RingBuffer::<u32, 4>::new().unwrap();
        let mut seq = 0u32;
        // Interleaved push/pop across > 3 full wraps of the 4-slot ring.
        for round in 0..15u32 {
            for _ in 0..3 {
                rb.push(seq).unwrap();
                seq = seq.wrapping_add(1);
            }
            // seq is now start+3; the three pops must yield start..start+3.
            for k in 0..3u32 {
                assert_eq!(rb.pop(), Some(seq - 3 + k), "round {}", round);
            }
        }
        assert!(rb.is_empty());
        assert_eq!(rb.dropped(), 0);
    }

    #[test]
    fn fill_drain_refill_after_wrap() {
        let mut rb = RingBuffer::<u32, 8>::new().unwrap();
        for i in 0..5u32 {
            rb.push(i).unwrap();
        }
        for _ in 0..5 {
            rb.pop().unwrap();
        }
        // head/tail are now at 5; push 8 more to force a full wrap.
        for i in 0..8u32 {
            rb.push(100 + i).unwrap();
        }
        for i in 0..8u32 {
            assert_eq!(rb.pop(), Some(100 + i));
        }
    }

    #[test]
    fn clear_resets_contents_not_drops() {
        let mut rb = RingBuffer::<u32, 4>::new().unwrap();
        rb.push(1).unwrap();
        rb.push(2).unwrap();
        for _ in 0..3 {
            let _ = rb.push(3); // fill + overflow
        }
        assert_eq!(rb.dropped(), 1);
        rb.clear();
        assert!(rb.is_empty());
        assert_eq!(rb.pop(), None);
        assert_eq!(rb.dropped(), 1, "drop counter survives clear (audit trail)");
        rb.push(9).unwrap();
        assert_eq!(rb.pop(), Some(9));
    }

    #[test]
    fn len_empty_full_transitions() {
        let mut rb = RingBuffer::<u32, 2>::new().unwrap();
        assert!(rb.is_empty() && !rb.is_full() && rb.is_empty());
        rb.push(1).unwrap();
        assert!(!rb.is_empty() && !rb.is_full() && rb.len() == 1);
        rb.push(2).unwrap();
        assert!(!rb.is_empty() && rb.is_full() && rb.len() == 2);
        rb.pop();
        assert!(!rb.is_full() && rb.len() == 1);
    }
}
