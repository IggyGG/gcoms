use std::collections::HashMap;
use std::collections::VecDeque;

/// LRU set of recently-seen message ids. A repeat sighting refreshes the id's
/// recency so a steadily-referenced message is not evicted out from under an
/// active flow while genuinely stale ids age out. `check_and_insert` returns
/// true only for a first sighting.
pub struct Dedup {
    seen: HashMap<[u8; 16], u64>,
    order: VecDeque<([u8; 16], u64)>,
    clock: u64,
    cap: usize,
}

impl Dedup {
    pub fn new(cap: usize) -> Self {
        Dedup {
            seen: HashMap::with_capacity(cap.min(1024)),
            order: VecDeque::with_capacity(cap.min(1024)),
            clock: 0,
            cap: cap.max(1),
        }
    }

    pub fn check_and_insert(&mut self, id: [u8; 16]) -> bool {
        self.clock += 1;
        if let Some(stamp) = self.seen.get_mut(&id) {
            // Seen before: refresh recency (LRU touch), report not-unique.
            *stamp = self.clock;
            self.order.push_back((id, self.clock));
            self.compact();
            return false;
        }
        self.seen.insert(id, self.clock);
        self.order.push_back((id, self.clock));
        self.evict();
        true
    }

    /// Drop the oldest live entries until we are within capacity. An entry in
    /// `order` is live only if its stamp still matches `seen`; superseded
    /// stamps (from an LRU touch) are skipped.
    fn evict(&mut self) {
        while self.seen.len() > self.cap {
            let Some((id, stamp)) = self.order.pop_front() else {
                break;
            };
            if self.seen.get(&id) == Some(&stamp) {
                self.seen.remove(&id);
            }
        }
    }

    /// Bound the bookkeeping deque, which can hold stale (superseded) stamps
    /// after repeated touches, without dropping any live entry.
    fn compact(&mut self) {
        while self.order.len() > self.cap * 2 {
            let Some((id, stamp)) = self.order.pop_front() else {
                break;
            };
            if self.seen.get(&id) == Some(&stamp) {
                // Still live: re-append so recency order is preserved.
                self.order.push_back((id, stamp));
                break;
            }
        }
    }

    pub fn forget(&mut self, id: [u8; 16]) {
        self.seen.remove(&id);
        self.order.retain(|(entry, _)| *entry != id);
    }

    pub fn forget_all(&mut self) {
        self.seen.clear();
        self.order.clear();
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> [u8; 16] {
        [n; 16]
    }

    #[test]
    fn first_sighting_is_unique() {
        let mut d = Dedup::new(8);
        assert!(d.check_and_insert(id(1)));
        assert!(!d.check_and_insert(id(1)));
        assert!(d.check_and_insert(id(2)));
    }

    #[test]
    fn evicts_oldest_at_cap() {
        let mut d = Dedup::new(2);
        d.check_and_insert(id(1));
        d.check_and_insert(id(2));
        d.check_and_insert(id(3));
        assert_eq!(d.len(), 2);
        assert!(
            d.check_and_insert(id(1)),
            "oldest forgotten, seen again as new"
        );
        assert!(
            !d.check_and_insert(id(3)),
            "recently inserted still tracked"
        );
    }

    #[test]
    fn touch_refreshes_recency() {
        // With cap 2: insert 1, 2, then touch 1 so 2 becomes the oldest;
        // inserting 3 must evict 2, not the just-touched 1.
        let mut d = Dedup::new(2);
        d.check_and_insert(id(1));
        d.check_and_insert(id(2));
        assert!(!d.check_and_insert(id(1)), "1 touched");
        d.check_and_insert(id(3));
        assert_eq!(d.len(), 2);
        assert!(!d.check_and_insert(id(1)), "touched 1 survived");
        assert!(d.check_and_insert(id(2)), "untouched 2 was evicted");
    }

    #[test]
    fn forget_all_resets() {
        let mut d = Dedup::new(8);
        d.check_and_insert(id(1));
        d.forget_all();
        assert!(d.is_empty());
        assert!(d.check_and_insert(id(1)));
    }
}
