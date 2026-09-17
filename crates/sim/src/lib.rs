use gcoms_gossip::{NodeId, Overlay, OverlayConfig, PeerDescriptor};
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use std::collections::{BinaryHeap, VecDeque};

#[derive(Clone, Debug)]
pub struct SimConfig {
    pub nodes: usize,
    pub duration_ms: u64,
    pub round_ms: f64,
    pub jitter: f64,
    pub net_delay_ms: f64,
    pub churn_per_hour: f64,
    pub avg_downtime_ms: u64,
    pub message_times_ms: Vec<u64>,
    pub pex_per_round: u32,
    pub overlay: OverlayConfig,
    pub seed: u64,
}

impl SimConfig {
    pub fn quick() -> Self {
        SimConfig {
            nodes: 300,
            duration_ms: 30_000,
            round_ms: 3000.0,
            jitter: 0.25,
            net_delay_ms: 100.0,
            churn_per_hour: 0.0,
            avg_downtime_ms: 30_000,
            message_times_ms: vec![8_000, 18_000],
            pex_per_round: 2,
            overlay: OverlayConfig::default(),
            seed: 7,
        }
    }

    pub fn full() -> Self {
        SimConfig {
            nodes: 5000,
            duration_ms: 120_000,
            round_ms: 3000.0,
            jitter: 0.25,
            net_delay_ms: 100.0,
            churn_per_hour: 0.3,
            avg_downtime_ms: 20_000,
            message_times_ms: vec![20_000, 40_000, 60_000, 80_000, 100_000],
            pex_per_round: 2,
            overlay: OverlayConfig::default(),
            seed: 7,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Event {
    Round(NodeId),
    MsgStart(usize, NodeId),
    MsgArrive(usize, NodeId, NodeId, u32),
    Pex(NodeId),
    Down(NodeId),
    Up(NodeId),
}

#[derive(Clone, Copy, Debug)]
struct Scheduled {
    at: u64,
    seq: u64,
    event: Event,
}

impl Eq for Scheduled {}
impl PartialEq for Scheduled {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at && self.seq == other.seq
    }
}
impl PartialOrd for Scheduled {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Scheduled {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.at, self.seq).cmp(&(other.at, other.seq)).reverse()
    }
}

#[derive(Clone, Debug)]
pub struct CoverRow {
    pub round_ms: u64,
    pub cover_prob: f64,
    pub window_s: u64,
    pub rate_matched: bool,
    pub idle_fpr: f64,
    pub active_tpr: f64,
    pub best_accuracy: f64,
    pub idle_kibps: f64,
}

pub fn cover_sweep(rounds_ms: &[u64], probs: &[f64], window_s: u64) -> Vec<CoverRow> {
    let mut rng = StdRng::seed_from_u64(99);
    let nodes = 2000usize;
    let mut out = Vec::new();
    for &round_ms in rounds_ms {
        for &p in probs {
            let ticks = (window_s * 1000) / round_ms;
            for rate_matched in [false, true] {
                let mut idle_counts = vec![0u32; nodes];
                let mut active_counts = vec![0u32; nodes];
                let active_p = if rate_matched { p } else { 0.95 };
                for i in 0..nodes {
                    for _ in 0..ticks {
                        if rng.gen::<f64>() < p {
                            idle_counts[i] += 1;
                        }
                    }
                    for _ in 0..ticks {
                        if rng.gen::<f64>() < active_p {
                            active_counts[i] += 1;
                        }
                    }
                }
                let mut best = (0.0f64, 0.0f64, 0.0f64);
                for k in 1..=ticks as u32 {
                    let fpr = idle_counts.iter().filter(|c| **c >= k).count() as f64 / nodes as f64;
                    let tpr =
                        active_counts.iter().filter(|c| **c >= k).count() as f64 / nodes as f64;
                    let acc = 0.5 * (tpr + (1.0 - fpr));
                    if acc > best.2 {
                        best = (fpr, tpr, acc);
                    }
                }
                let emissions_per_idle = p * ticks as f64;
                let cell_kib = 4.0;
                out.push(CoverRow {
                    round_ms,
                    cover_prob: p,
                    window_s,
                    rate_matched,
                    idle_fpr: best.0,
                    active_tpr: best.1,
                    best_accuracy: best.2,
                    idle_kibps: emissions_per_idle * cell_kib / window_s as f64,
                });
            }
        }
    }
    out
}

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub nodes: usize,
    pub messages: usize,
    pub delivery_ratio: f64,
    pub p50_ms: u64,
    pub p90_ms: u64,
    pub p99_ms: u64,
    pub max_ms: u64,
    pub dup_ratio: f64,
    pub per_node_kibps_p99: f64,
    pub hops_mean: f64,
    pub avg_view_len: f64,
    pub dropped_offline: u64,
}

struct SimNode {
    overlay: Overlay,
    online: bool,
    pending: Vec<(usize, Option<NodeId>)>,
    bytes_out: u64,
    recent: VecDeque<usize>,
}

pub fn run(cfg: &SimConfig) -> Report {
    let mut rng = StdRng::seed_from_u64(cfg.seed);
    let mut seq: u64 = 0;
    let mut heap: BinaryHeap<Scheduled> = BinaryHeap::new();
    let cell_bytes: u64 = 4096;
    let pex_cell_bytes: u64 = 1024;

    let mut nodes: Vec<SimNode> = (0..cfg.nodes as u64)
        .map(|i| {
            let overlay = Overlay::new(i, cfg.overlay, cfg.seed ^ i);
            SimNode {
                overlay,
                online: true,
                pending: Vec::new(),
                bytes_out: 0,
                recent: VecDeque::new(),
            }
        })
        .collect();

    let designated = [0u64, 1, 2];
    for i in 0..cfg.nodes as u64 {
        let mut boot = vec![
            PeerDescriptor {
                id: designated[0],
                pseudonym: [0; 32],
            },
            PeerDescriptor {
                id: designated[1],
                pseudonym: [1; 32],
            },
            PeerDescriptor {
                id: designated[2],
                pseudonym: [2; 32],
            },
        ];
        if i > 3 {
            boot.push(PeerDescriptor {
                id: (i * 7919) % cfg.nodes as u64,
                pseudonym: [3; 32],
            });
        }
        nodes[i as usize].overlay.bootstrap(&boot);
    }

    for i in 0..cfg.nodes as u64 {
        let first = rng.gen_range(0.0..cfg.round_ms);
        heap.push(Scheduled {
            at: first as u64,
            seq: {
                seq += 1;
                seq
            },
            event: Event::Round(i),
        });
        for p in 0..cfg.pex_per_round {
            let phase = rng.gen_range(0.0..cfg.round_ms)
                + (p as f64) * (cfg.round_ms / cfg.pex_per_round as f64);
            heap.push(Scheduled {
                at: phase as u64 % cfg.duration_ms.max(1),
                seq: {
                    seq += 1;
                    seq
                },
                event: Event::Pex(i),
            });
        }
        if cfg.churn_per_hour > 0.0 {
            let rate = cfg.churn_per_hour / 3600.0 / 1000.0;
            let next = -rng.gen::<f64>().ln() / rate;
            heap.push(Scheduled {
                at: next as u64,
                seq: {
                    seq += 1;
                    seq
                },
                event: Event::Down(i),
            });
        }
    }

    for (mi, t) in cfg.message_times_ms.iter().enumerate() {
        let origin = rng.gen_range(0..cfg.nodes as u64);
        heap.push(Scheduled {
            at: *t,
            seq: {
                seq += 1;
                seq
            },
            event: Event::MsgStart(mi, origin),
        });
    }

    let msg_count = cfg.message_times_ms.len();
    let mut delivered: Vec<Vec<Option<u64>>> = vec![vec![None; cfg.nodes]; msg_count];
    let mut hops: Vec<Vec<u32>> = vec![Vec::new(); msg_count];
    let mut t0: Vec<u64> = vec![0; msg_count];
    let mut denominator: Vec<usize> = vec![0; msg_count];
    let mut eligible: Vec<Vec<bool>> = vec![vec![true; cfg.nodes]; msg_count];
    let mut dup_receptions: u64 = 0;
    let mut unique_receptions: u64 = 0;
    let mut dropped_offline: u64 = 0;
    let mut origin_nodes: Vec<NodeId> = vec![0; msg_count];

    while let Some(s) = heap.pop() {
        if s.at > cfg.duration_ms {
            break;
        }
        let now = s.at;
        match s.event {
            Event::Round(id) => {
                let idx = id as usize;
                let round = rng.gen_range(1.0 - cfg.jitter..=1.0 + cfg.jitter);
                let next = (now as f64 + cfg.round_ms * round) as u64;
                heap.push(Scheduled {
                    at: next,
                    seq: {
                        seq += 1;
                        seq
                    },
                    event: Event::Round(id),
                });
                if !nodes[idx].online {
                    continue;
                }
                let pending = std::mem::take(&mut nodes[idx].pending);
                for (mi, from) in pending {
                    let targets = nodes[idx].overlay.forward_targets(from);
                    nodes[idx].bytes_out += targets.len() as u64 * cell_bytes;
                    for t in targets {
                        let delay = cfg.net_delay_ms * rng.gen_range(0.5..1.5);
                        heap.push(Scheduled {
                            at: now + delay as u64,
                            seq: {
                                seq += 1;
                                seq
                            },
                            event: Event::MsgArrive(mi, t, id, 1),
                        });
                    }
                }
            }
            Event::MsgStart(mi, origin) => {
                t0[mi] = now;
                origin_nodes[mi] = origin;
                denominator[mi] = nodes.iter().filter(|n| n.online).count() - 1;
                nodes[origin as usize]
                    .overlay
                    .first_sighting([mi as u8; 16]);
                nodes[origin as usize].pending.push((mi, None));
                let mut direct: Vec<NodeId> = Vec::new();
                while direct.len() < cfg.overlay.direct_push.min(cfg.nodes - 1) {
                    let t = rng.gen_range(0..cfg.nodes as u64);
                    if t != origin && !direct.contains(&t) {
                        direct.push(t);
                    }
                }
                nodes[origin as usize].bytes_out += direct.len() as u64 * cell_bytes;
                for t in direct {
                    let delay = cfg.net_delay_ms * rng.gen_range(0.5..1.5);
                    heap.push(Scheduled {
                        at: now + delay as u64,
                        seq: {
                            seq += 1;
                            seq
                        },
                        event: Event::MsgArrive(mi, t, origin, 1),
                    });
                }
            }
            Event::MsgArrive(mi, to, from, hop) => {
                let idx = to as usize;
                if !nodes[idx].online || !eligible[mi][idx] {
                    dropped_offline += 1;
                    continue;
                }
                if nodes[idx].overlay.first_sighting([mi as u8; 16]) {
                    unique_receptions += 1;
                    delivered[mi][idx] = Some(now - t0[mi]);
                    hops[mi].push(hop + 1);
                    nodes[idx].recent.push_back(mi);
                    if nodes[idx].recent.len() > cfg.overlay.have_list {
                        nodes[idx].recent.pop_front();
                    }
                    nodes[idx].pending.push((mi, Some(from)));
                } else {
                    dup_receptions += 1;
                }
            }
            Event::Pex(id) => {
                let idx = id as usize;
                heap.push(Scheduled {
                    at: now + (cfg.round_ms * rng.gen_range(0.75..1.25)) as u64,
                    seq: {
                        seq += 1;
                        seq
                    },
                    event: Event::Pex(id),
                });
                if !nodes[idx].online {
                    continue;
                }
                if let Some((partner, descs)) = nodes[idx].overlay.pex_outbound() {
                    nodes[idx].bytes_out += pex_cell_bytes;
                    let p = partner as usize;
                    if p < cfg.nodes && nodes[p].online {
                        nodes[p].overlay.pex_absorb(id, &descs);
                        let reply = nodes[p]
                            .overlay
                            .view
                            .random_descriptors(cfg.overlay.pex_batch);
                        nodes[idx].overlay.pex_absorb(partner, &reply);
                        nodes[idx].bytes_out += pex_cell_bytes;
                        let recent_p: Vec<usize> = nodes[p].recent.iter().copied().collect();
                        let recent_i: Vec<usize> = nodes[idx].recent.iter().copied().collect();
                        for msg in recent_p {
                            if nodes[idx].online
                                && eligible[msg][idx]
                                && nodes[idx].overlay.first_sighting([msg as u8; 16])
                            {
                                unique_receptions += 1;
                                delivered[msg][idx] = Some(now - t0[msg]);
                                hops[msg].push(1);
                                nodes[idx].recent.push_back(msg);
                                if nodes[idx].recent.len() > cfg.overlay.have_list {
                                    nodes[idx].recent.pop_front();
                                }
                                nodes[idx].pending.push((msg, Some(partner)));
                                nodes[p].bytes_out += cell_bytes;
                            }
                        }
                        for msg in recent_i {
                            if nodes[p].online
                                && eligible[msg][p]
                                && nodes[p].overlay.first_sighting([msg as u8; 16])
                            {
                                unique_receptions += 1;
                                delivered[msg][p] = Some(now - t0[msg]);
                                hops[msg].push(1);
                                nodes[p].recent.push_back(msg);
                                if nodes[p].recent.len() > cfg.overlay.have_list {
                                    nodes[p].recent.pop_front();
                                }
                                nodes[p].pending.push((msg, Some(id)));
                                nodes[idx].bytes_out += cell_bytes;
                            }
                        }
                    }
                }
            }
            Event::Down(id) => {
                let idx = id as usize;
                nodes[idx].online = false;
                nodes[idx].pending.clear();
                for mi in 0..msg_count {
                    if delivered[mi][idx].is_none() {
                        eligible[mi][idx] = false;
                    }
                }
                let rate = cfg.churn_per_hour / 3600.0 / 1000.0;
                let next = -rng.gen::<f64>().ln() / rate;
                heap.push(Scheduled {
                    at: now + next as u64,
                    seq: {
                        seq += 1;
                        seq
                    },
                    event: Event::Up(id),
                });
            }
            Event::Up(id) => {
                let idx = id as usize;
                nodes[idx].online = true;
                let boot = vec![
                    PeerDescriptor {
                        id: 0,
                        pseudonym: [0; 32],
                    },
                    PeerDescriptor {
                        id: 1,
                        pseudonym: [1; 32],
                    },
                    PeerDescriptor {
                        id: 2,
                        pseudonym: [2; 32],
                    },
                    PeerDescriptor {
                        id: (id.wrapping_mul(7919)) % cfg.nodes as u64,
                        pseudonym: [3; 32],
                    },
                ];
                nodes[idx].overlay.reset_session(&boot);
                let rate = cfg.churn_per_hour / 3600.0 / 1000.0;
                let next = -rng.gen::<f64>().ln() / rate;
                heap.push(Scheduled {
                    at: now + next as u64,
                    seq: {
                        seq += 1;
                        seq
                    },
                    event: Event::Down(id),
                });
            }
        }
    }

    let mut latencies: Vec<u64> = Vec::new();
    let mut total_delivered = 0usize;
    let mut total_expected = 0usize;
    for mi in 0..msg_count {
        let mut msg_lat: Vec<u64> = delivered[mi]
            .iter()
            .enumerate()
            .filter(|(i, d)| d.is_some() && eligible[mi][*i] && *i as u64 != origin_nodes[mi])
            .map(|(_, d)| d.unwrap())
            .collect();
        total_delivered += msg_lat.len();
        total_expected += eligible[mi]
            .iter()
            .filter(|e| **e)
            .count()
            .saturating_sub(1);
        latencies.append(&mut msg_lat);
    }
    latencies.sort_unstable();

    let pct = |p: f64| -> u64 {
        if latencies.is_empty() {
            return 0;
        }
        let idx = ((latencies.len() as f64) * p).ceil() as usize - 1;
        latencies[idx.min(latencies.len() - 1)]
    };

    let mut per_node_bytes: Vec<u64> = nodes.iter().map(|n| n.bytes_out).collect();
    per_node_bytes.sort_unstable();
    let dur_s = cfg.duration_ms as f64 / 1000.0;
    let p99_bytes = per_node_bytes[(per_node_bytes.len() as f64 * 0.99) as usize];
    let per_node_kibps_p99 = p99_bytes as f64 / 1024.0 / dur_s;

    let avg_view_len =
        nodes.iter().map(|n| n.overlay.view_len()).sum::<usize>() as f64 / cfg.nodes as f64;

    let all_hops: Vec<u32> = hops.iter().flatten().copied().collect();
    let hops_mean = if all_hops.is_empty() {
        0.0
    } else {
        all_hops.iter().sum::<u32>() as f64 / all_hops.len() as f64
    };

    #[cfg(feature = "per-msg-debug")]
    for mi in 0..msg_count {
        let mut l: Vec<u64> = delivered[mi]
            .iter()
            .enumerate()
            .filter(|(i, d)| d.is_some() && eligible[mi][*i] && *i as u64 != origin_nodes[mi])
            .map(|(_, d)| d.unwrap())
            .collect();
        l.sort_unstable();
        if !l.is_empty() {
            eprintln!(
                "msg {mi}: n={} p50={} p99={} max={}",
                l.len(),
                l[l.len() / 2],
                l[(l.len() as f64 * 0.99) as usize],
                l.last().unwrap()
            );
        }
    }

    Report {
        nodes: cfg.nodes,
        messages: msg_count,
        delivery_ratio: total_delivered as f64 / total_expected.max(1) as f64,
        p50_ms: pct(0.50),
        p90_ms: pct(0.90),
        p99_ms: pct(0.99),
        max_ms: pct(1.0),
        dup_ratio: dup_receptions as f64 / (dup_receptions + unique_receptions).max(1) as f64,
        per_node_kibps_p99,
        hops_mean,
        avg_view_len,
        dropped_offline,
    }
}
