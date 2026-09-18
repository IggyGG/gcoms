//! Local queue-maintenance CPU measurement. Synthetic capabilities and a fixed
//! clock isolate replay cleanup; this is not network/application goodput evidence.
use gcoms_core::{Cell, CellType};
use gcoms_node::{
    lease::{Capabilities, LeaseCreate, LeaseLimits},
    queues::{GrantRequest, LeaseStore, StoreConfig},
    relay::{RelayPush, UnauthenticatedRelayPush},
};
use std::{hint::black_box, time::Instant};

const QUEUES: u64 = 64;
const PUSHES: u64 = 128;
const READS: usize = 5000;
const REPEATS: usize = 5;
const NOW: u64 = 1_000_000;

fn main() {
    let pin = [9; 32];
    let caps = Capabilities {
        push: [5; 32],
        sub: [6; 32],
        admin: [7; 32],
    };
    let limits = LeaseLimits {
        max_queue_cells: 4,
        max_queue_bytes: 4096,
    };
    let mut store = LeaseStore::new(pin, StoreConfig::default()).unwrap();
    let mut hot = [0; 32];
    for index in 1..=QUEUES {
        let mut queue = [0; 32];
        queue[..8].copy_from_slice(&index.to_be_bytes());
        hot = queue;
        let grant = store
            .issue_grant(
                GrantRequest {
                    queue_id: queue,
                    epoch: 1,
                    limits,
                },
                NOW,
            )
            .unwrap();
        let create = LeaseCreate {
            queue_id: queue,
            epoch: 1,
            lease_expiry: NOW + 3600,
            queue_cells: limits.max_queue_cells,
            queue_bytes: limits.max_queue_bytes,
            capabilities: caps,
            nonce: [31; 16],
            grant: grant.wire,
        };
        store
            .create_lease(&create.encode(&pin).unwrap(), NOW)
            .unwrap();
        for counter in 1..=PUSHES {
            let mut nonce = [0; 16];
            nonce[..8].copy_from_slice(&counter.to_be_bytes());
            let push = RelayPush {
                queue_id: queue,
                epoch: 1,
                push_nonce: nonce,
                push_expiry: NOW + 600,
                msg: (counter == 1).then(|| Cell::new(CellType::Msg, 0, 0, vec![17; 128])),
            };
            let push =
                UnauthenticatedRelayPush::parse(push.encode_into_cell(&caps.push, &pin).unwrap())
                    .unwrap();
            store.authenticate_push(push, NOW).unwrap();
        }
    }
    let mut samples = Vec::new();
    for _ in 0..REPEATS {
        let start = Instant::now();
        for _ in 0..READS {
            assert!(black_box(store.peek(black_box(&hot), black_box(NOW + 1))).is_some());
        }
        samples.push(start.elapsed().as_nanos() as u64);
    }
    assert_eq!(store.queue_count(NOW + 1), QUEUES as usize);
    assert_eq!(
        store.total_queue_bytes(),
        QUEUES * (128 + gcoms_core::HEADER_LEN as u64)
    );
    println!(
        "{}",
        serde_json::json!({"scope":"queue-maintenance CPU only; no network, privacy or application qualification", "queues":QUEUES, "push_replays_per_queue":PUSHES, "reads_per_repeat":READS, "samples_ns":samples})
    );
}
