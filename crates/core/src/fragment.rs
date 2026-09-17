use alloc::collections::VecDeque;
use alloc::vec::Vec;

pub const FRAGMENT_TABLE_CAP: usize = 64;
/// No single reassembly may exceed one maximum message (SPEC §7.2).
pub const FRAGMENT_MESSAGE_CAP: usize = crate::MAX_MESSAGE;
/// Aggregate bytes held across every in-progress reassembly.
pub const FRAGMENT_TOTAL_CAP: usize = FRAGMENT_TABLE_CAP * FRAGMENT_MESSAGE_CAP;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId(pub [u8; 16]);

#[derive(Debug, Default)]
pub struct FragmentBuffer {
    cap: usize,
    message_cap: usize,
    total_cap: usize,
    total: usize,
    slots: VecDeque<(MessageId, Vec<u8>)>,
}

impl FragmentBuffer {
    pub fn new() -> Self {
        Self::with_caps(FRAGMENT_TABLE_CAP, FRAGMENT_MESSAGE_CAP, FRAGMENT_TOTAL_CAP)
    }

    pub fn with_cap(cap: usize) -> Self {
        Self::with_caps(cap, FRAGMENT_MESSAGE_CAP, cap * FRAGMENT_MESSAGE_CAP)
    }

    /// Slot, per-message byte, and aggregate byte bounds. A fragment that
    /// would push a message or the table past its bound drops that message.
    pub fn with_caps(cap: usize, message_cap: usize, total_cap: usize) -> Self {
        FragmentBuffer {
            cap,
            message_cap,
            total_cap,
            total: 0,
            slots: VecDeque::new(),
        }
    }

    pub fn bytes(&self) -> usize {
        self.total
    }

    fn remove_at(&mut self, pos: usize) -> Option<Vec<u8>> {
        let (_, buf) = self.slots.remove(pos)?;
        self.total -= buf.len();
        Some(buf)
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    pub fn push(&mut self, id: MessageId, last: bool, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() > self.message_cap {
            // Oversized on its own: drop any partial state for this id too.
            if let Some(pos) = self.slots.iter().position(|(i, _)| *i == id) {
                self.remove_at(pos);
            }
            return None;
        }
        if let Some(pos) = self.slots.iter().position(|(i, _)| *i == id) {
            if self.slots[pos].1.len() + data.len() > self.message_cap {
                self.remove_at(pos);
                return None;
            }
        } else {
            while self.slots.len() >= self.cap {
                self.remove_at(0);
            }
            self.slots.push_back((id, Vec::with_capacity(data.len())));
        }
        while self.total + data.len() > self.total_cap {
            // Evict the oldest other reassembly; never the one being fed.
            let Some(victim) = self.slots.iter().position(|(i, _)| *i != id) else {
                break;
            };
            self.remove_at(victim);
        }
        let pos = self.slots.iter().position(|(i, _)| *i == id)?;
        self.slots[pos].1.extend_from_slice(data);
        self.total += data.len();
        if last {
            return self.remove_at(pos);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> MessageId {
        MessageId([n; 16])
    }

    #[test]
    fn reassembles_in_arrival_order() {
        let mut fb = FragmentBuffer::new();
        assert_eq!(fb.push(id(1), false, b"hello "), None);
        assert_eq!(fb.push(id(1), false, b"frag"), None);
        assert_eq!(
            fb.push(id(1), true, b" world"),
            Some(b"hello frag world".to_vec())
        );
        assert!(fb.is_empty());
    }

    #[test]
    fn interleaved_messages() {
        let mut fb = FragmentBuffer::new();
        fb.push(id(1), false, b"a1");
        fb.push(id(2), false, b"b1");
        fb.push(id(1), false, b"a2");
        assert_eq!(fb.push(id(2), true, b"b2"), Some(b"b1b2".to_vec()));
        assert_eq!(fb.push(id(1), true, b"a3"), Some(b"a1a2a3".to_vec()));
    }

    #[test]
    fn single_fragment_message() {
        let mut fb = FragmentBuffer::new();
        assert_eq!(fb.push(id(9), true, b"whole"), Some(b"whole".to_vec()));
    }

    #[test]
    fn restarts_after_completion() {
        let mut fb = FragmentBuffer::new();
        fb.push(id(1), true, b"done");
        assert_eq!(fb.len(), 0);
        assert_eq!(fb.push(id(1), false, b"x"), None);
        assert_eq!(fb.len(), 1);
        assert_eq!(fb.push(id(1), true, b"y"), Some(b"xy".to_vec()));
    }

    #[test]
    fn oversized_message_is_dropped_and_total_bytes_are_bounded() {
        let mut fb = FragmentBuffer::with_caps(4, 8, 12);
        assert_eq!(fb.push(id(1), false, b"12345"), None);
        // exceeds the 8-byte per-message cap: message 1 is discarded
        assert_eq!(fb.push(id(1), false, b"6789"), None);
        assert_eq!(fb.len(), 0);
        assert_eq!(fb.bytes(), 0);
        // aggregate cap: the third message evicts the oldest
        fb.push(id(2), false, b"aaaa");
        fb.push(id(3), false, b"bbbb");
        assert_eq!(fb.bytes(), 8);
        fb.push(id(4), false, b"cccccc");
        assert!(fb.bytes() <= 12);
        // the evicted message lost its prefix: it restarts from scratch
        assert_eq!(fb.push(id(2), true, b"x"), Some(b"x".to_vec()));
        assert_eq!(fb.push(id(4), true, b"dd"), Some(b"ccccccdd".to_vec()));
        // a single fragment larger than the message cap never allocates
        assert_eq!(fb.push(id(9), true, &[0; 9]), None);
        assert_eq!(
            fb.bytes(),
            fb.slots.iter().map(|(_, b)| b.len()).sum::<usize>()
        );
    }

    #[test]
    fn drops_oldest_at_capacity() {
        let mut fb = FragmentBuffer::with_cap(2);
        fb.push(id(1), false, b"old");
        fb.push(id(2), false, b"mid");
        fb.push(id(3), false, b"new");
        assert_eq!(fb.len(), 2);
        assert_eq!(fb.push(id(1), false, b"orphan"), None);
        assert_eq!(fb.len(), 2);
        assert_eq!(fb.push(id(3), true, b"new2"), Some(b"newnew2".to_vec()));
    }
}
