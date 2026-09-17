use crate::dedup::Dedup;
use crate::view::{PeerDescriptor, View};
use crate::{NodeId, DEDUP_LRU, PEX_BATCH, VIEW_SIZE};
use rand::rngs::StdRng;
use rand::RngCore;
use rand::SeedableRng;

#[derive(Clone, Copy, Debug)]
pub struct OverlayConfig {
    pub view_size: usize,
    pub dedup_cap: usize,
    pub origin_fanout: usize,
    pub forward_fanout: usize,
    pub forward_prob: f64,
    pub direct_push: usize,
    pub pex_batch: usize,
    pub have_list: usize,
}

impl Default for OverlayConfig {
    fn default() -> Self {
        OverlayConfig {
            view_size: VIEW_SIZE,
            dedup_cap: DEDUP_LRU,
            origin_fanout: 4,
            forward_fanout: 1,
            forward_prob: 0.5,
            direct_push: 16,
            pex_batch: PEX_BATCH,
            have_list: 16,
        }
    }
}

pub struct Overlay {
    me: NodeId,
    pseudonym: [u8; 32],
    pub view: View,
    dedup: Dedup,
    pub cfg: OverlayConfig,
    rng: StdRng,
}

impl Overlay {
    pub fn new(me: NodeId, cfg: OverlayConfig, seed: u64) -> Self {
        let view = View::new(me, cfg.view_size, seed);
        let dedup = Dedup::new(cfg.dedup_cap);
        let mut rng = StdRng::seed_from_u64(seed ^ 0x5EED);
        use rand::RngCore;
        let mut pseudonym = [0u8; 32];
        rng.fill_bytes(&mut pseudonym);
        Overlay {
            me,
            pseudonym,
            view,
            dedup,
            cfg,
            rng,
        }
    }

    pub fn me(&self) -> NodeId {
        self.me
    }

    pub fn self_descriptor(&self) -> PeerDescriptor {
        PeerDescriptor {
            id: self.me,
            pseudonym: self.pseudonym,
        }
    }

    pub fn bootstrap(&mut self, peers: &[PeerDescriptor]) {
        for p in peers {
            self.view.absorb(*p);
        }
    }

    pub fn first_sighting(&mut self, msg_id: [u8; 16]) -> bool {
        self.dedup.check_and_insert(msg_id)
    }

    /// Roll back a receive whose durable transaction failed, preserving all
    /// other duplicate markers and the existing peer view.
    pub fn forget_sighting(&mut self, msg_id: [u8; 16]) {
        self.dedup.forget(msg_id);
    }

    pub fn origin_targets(&mut self) -> Vec<NodeId> {
        self.view.random_targets(self.cfg.origin_fanout, &[])
    }

    pub fn forward_targets(&mut self, from: Option<NodeId>) -> Vec<NodeId> {
        use rand::Rng;
        if self.rng.gen::<f64>() >= self.cfg.forward_prob {
            return Vec::new();
        }
        let exclude = from.map(|f| vec![f]).unwrap_or_default();
        self.view.random_targets(self.cfg.forward_fanout, &exclude)
    }

    pub fn pex_outbound(&mut self) -> Option<(NodeId, Vec<PeerDescriptor>)> {
        let partner = self.view.random_entry()?;
        let mut descriptors = vec![self.self_descriptor()];
        descriptors.extend(self.view.random_descriptors(self.cfg.pex_batch - 1));
        Some((partner, descriptors))
    }

    /// Maximum descriptors from one PEX partner absorbed into the view per
    /// exchange. Caps how fast a single (possibly malicious) partner can
    /// rewrite our sample, blunting eclipse attempts; the remainder of an
    /// over-large batch is ignored this round. The partner's own descriptor
    /// (always first in a well-formed batch) is not counted against the cap.
    pub const MAX_ABSORB_PER_SOURCE: usize = 4;

    pub fn pex_absorb(&mut self, from: NodeId, descriptors: &[PeerDescriptor]) {
        let mut taken = 0usize;
        for d in descriptors {
            if d.id == from {
                // The partner vouching for itself is always allowed.
                self.view.absorb(*d);
                continue;
            }
            if taken >= Self::MAX_ABSORB_PER_SOURCE {
                break;
            }
            if self.view.absorb(*d) {
                taken += 1;
            }
        }
    }

    pub fn reset_session(&mut self, bootstrap: &[PeerDescriptor]) {
        self.dedup.forget_all();
        let seed = self.rng.next_u64();
        self.view = View::new(self.me, self.cfg.view_size, seed);
        self.bootstrap(bootstrap);
    }

    pub fn view_len(&self) -> usize {
        self.view.len()
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

    fn mesh(n: u64) -> Vec<Overlay> {
        let mut nodes: Vec<Overlay> = (0..n)
            .map(|i| {
                let mut o = Overlay::new(i, OverlayConfig::default(), 1000 + i);
                o.bootstrap(&[
                    desc(0),
                    desc(1),
                    desc(2),
                    desc((i + 1) % n),
                    desc((i + 2) % n),
                ]);
                o
            })
            .collect();
        for _ in 0..40 {
            for i in 0..nodes.len() as u64 {
                let out = nodes[i as usize].pex_outbound().unwrap();
                let (partner, descs) = out;
                if (partner as usize) < nodes.len() {
                    let d = descs.clone();
                    nodes[partner as usize].pex_absorb(i, &d);
                }
            }
        }
        nodes
    }

    #[test]
    fn pex_converges_views() {
        let nodes = mesh(50);
        let avg = nodes.iter().map(|n| n.view_len()).sum::<usize>() / nodes.len();
        assert!(
            avg >= 20,
            "avg view {avg} should be near capacity after shuffles"
        );
    }

    #[test]
    fn view_graph_is_connected() {
        let nodes = mesh(60);
        let adjacency: Vec<Vec<NodeId>> = nodes.iter().map(|o| o.view.ids()).collect();
        let mut visited = vec![false; adjacency.len()];
        visited[0] = true;
        let mut queue = std::collections::VecDeque::from(vec![0usize]);
        while let Some(i) = queue.pop_front() {
            for next in &adjacency[i] {
                let j = *next as usize;
                if j < visited.len() && !visited[j] {
                    visited[j] = true;
                    queue.push_back(j);
                }
            }
        }
        let reached = visited.iter().filter(|v| **v).count();
        assert_eq!(
            reached, 60,
            "view graph must be connected, reached {reached}"
        );
    }

    #[test]
    fn reset_session_clears_dedup_and_view() {
        let mut o = Overlay::new(9, OverlayConfig::default(), 3);
        o.bootstrap(&[desc(1), desc(2)]);
        assert!(o.first_sighting([1; 16]));
        o.reset_session(&[desc(3)]);
        assert_eq!(o.view_len(), 1);
        assert!(o.first_sighting([1; 16]), "dedup cleared on reset");
    }

    #[test]
    fn failed_receive_rollback_preserves_other_messages_and_peer_view() {
        let mut overlay = Overlay::new(9, OverlayConfig::default(), 3);
        overlay.bootstrap(&[desc(1), desc(2)]);
        assert!(overlay.first_sighting([1; 16]));
        assert!(overlay.first_sighting([2; 16]));
        assert!(!overlay.first_sighting([1; 16]));
        let view = overlay.view.ids();
        overlay.forget_sighting([1; 16]);
        overlay.forget_sighting([3; 16]);
        assert!(overlay.first_sighting([1; 16]));
        assert!(!overlay.first_sighting([2; 16]));
        assert_eq!(overlay.view.ids(), view);
    }
}
