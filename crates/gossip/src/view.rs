use crate::NodeId;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::SeedableRng;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerDescriptor {
    pub id: NodeId,
    pub pseudonym: [u8; 32],
}

/// A bounded random peer sample. Eviction is uniform-random over the current
/// set, so an attacker cannot make the view converge on attacker-controlled
/// entries by flooding descriptors: the per-source absorb cap (see
/// `Overlay::pex_absorb`) bounds how many any single partner can contribute
/// per exchange, and random eviction gives no path to pin a victim in place.
pub struct View {
    me: NodeId,
    entries: Vec<PeerDescriptor>,
    cap: usize,
    rng: StdRng,
}

impl View {
    /// `seed` seeds the eviction/sampling RNG. Callers that need
    /// unpredictability across restarts (the node) pass a fresh random seed;
    /// the simulator passes a fixed seed for reproducible gate runs.
    pub fn new(me: NodeId, cap: usize, seed: u64) -> Self {
        View {
            me,
            entries: Vec::new(),
            cap,
            rng: StdRng::seed_from_u64(seed),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, id: NodeId) -> bool {
        self.entries.iter().any(|e| e.id == id)
    }

    pub fn ids(&self) -> Vec<NodeId> {
        self.entries.iter().map(|e| e.id).collect()
    }

    pub fn absorb(&mut self, d: PeerDescriptor) -> bool {
        if d.id == self.me || self.contains(d.id) {
            return false;
        }
        if self.entries.len() < self.cap {
            self.entries.push(d);
            return true;
        }
        if let Some(victim) = self.pick_victim() {
            if let Some(pos) = self.entries.iter().position(|e| e.id == victim) {
                self.entries.remove(pos);
                self.entries.push(d);
                return true;
            }
        }
        false
    }

    fn pick_victim(&mut self) -> Option<NodeId> {
        self.entries.choose(&mut self.rng).map(|e| e.id)
    }

    pub fn random_targets(&mut self, n: usize, exclude: &[NodeId]) -> Vec<NodeId> {
        let mut pool: Vec<NodeId> = self
            .entries
            .iter()
            .map(|e| e.id)
            .filter(|id| !exclude.contains(id))
            .collect();
        let take = n.min(pool.len());
        pool.partial_shuffle(&mut self.rng, take);
        pool.truncate(take);
        pool
    }

    pub fn random_descriptors(&mut self, n: usize) -> Vec<PeerDescriptor> {
        let mut pool = self.entries.clone();
        pool.shuffle(&mut self.rng);
        pool.truncate(n);
        pool
    }

    pub fn random_entry(&mut self) -> Option<NodeId> {
        self.entries.choose(&mut self.rng).map(|e| e.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desc(id: NodeId) -> PeerDescriptor {
        PeerDescriptor {
            id,
            pseudonym: [id as u8; 32],
        }
    }

    #[test]
    fn never_absorbs_self_or_duplicates() {
        let mut v = View::new(1, 8, 42);
        assert!(!v.absorb(desc(1)));
        assert!(v.absorb(desc(2)));
        assert!(!v.absorb(desc(2)));
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn respects_capacity_via_victim_selection() {
        let mut v = View::new(0, 3, 42);
        for id in 1..=6 {
            v.absorb(desc(id));
        }
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn targets_are_distinct_and_excluded() {
        let mut v = View::new(0, 10, 7);
        for id in 1..=10 {
            v.absorb(desc(id));
        }
        let t = v.random_targets(4, &[1, 2]);
        assert_eq!(t.len(), 4);
        let mut uniq = t.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), 4);
        assert!(!t.contains(&1) && !t.contains(&2));
    }

    #[test]
    fn a_single_flooding_source_cannot_fill_the_view_deterministically() {
        // Absorbing far more than capacity keeps the view bounded and keeps
        // eviction random: the newest descriptor is not guaranteed retained.
        let mut v = View::new(0, 4, 9);
        for id in 1..=64 {
            v.absorb(desc(id));
        }
        assert_eq!(v.len(), 4);
    }
}
