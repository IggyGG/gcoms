use gcoms_file_transfer::swarm::*;
use std::{collections::VecDeque, io::Cursor};

const CHANNEL: [u8; 32] = [43; 32];
const MEMBERS: [[u8; 32]; 2] = [[1; 32], [2; 32]];

fn cache() -> (tempfile::TempDir, Cache) {
    let dir = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(dir.path(), true).unwrap();
    let cache = Cache::open(dir.path(), [31; 32], CacheConfig::default()).unwrap();
    (dir, cache)
}

// Model durable local acceptance followed by two FIFO transport legs. Each
// direction drains one application every four seconds, within the native
// scheduler's observed delays. An accepted request's original 30-second timer
// runs while its ciphertext waits in that FIFO; its real response is verified
// through the engine and cache, without fabricating transport or file receipts.
fn transfer(contacts: bool, drain_seconds: u64) -> (u64, u64) {
    let (_source_dir, mut source) = cache();
    let (_target_dir, target) = cache();
    let bytes: Vec<_> = (0..PIECE_BYTES).map(|i| (i % 251) as u8).collect();
    let manifest = source
        .import(
            [13; 16],
            Scope {
                channel: CHANNEL,
                participants: MEMBERS.to_vec(),
            },
            "fifo.bin".into(),
            bytes.len() as u64,
            &mut Cursor::new(&bytes),
            1,
        )
        .unwrap();
    let constructor = if contacts {
        Engine::for_contacts
    } else {
        Engine::new
    };
    let mut engines = [constructor(source), constructor(target)];
    let peers = MEMBERS.map(|member| Peer {
        channel: CHANNEL,
        member,
    });
    for (index, engine) in engines.iter_mut().enumerate() {
        engine.set_members(CHANNEL, MEMBERS[index], MEMBERS);
    }
    engines[1]
        .receive(
            peers[0],
            Message::Offers {
                manifests: vec![manifest.clone()],
                next: None,
            },
            1,
        )
        .unwrap();
    engines[1].accept(manifest.id, 1).unwrap();
    engines[1]
        .receive(
            peers[0],
            Message::Have {
                id: manifest.id,
                start: 0,
                pieces: vec![true],
            },
            1,
        )
        .unwrap();
    let mut queues: [VecDeque<Action>; 2] = [VecDeque::new(), VecDeque::new()];
    for now in 2..240 {
        for from in 0..2 {
            for action in engines[from].tick(now).unwrap() {
                if matches!(action.message, Message::Want { .. }) {
                    engines[from].send_finished(action.send_token(), SendOutcome::HopAccepted, now);
                    queues[from].push_back(action);
                }
            }
        }
        if now % drain_seconds == 0 {
            for from in 0..2 {
                if let Some(action) = queues[from].pop_front() {
                    // Already admitted durable traffic cannot be withdrawn while
                    // queued, even when its block was verified in the meantime.
                    let decoded = Message::decode(&action.message.encode().unwrap()).unwrap();
                    let replies = engines[1 - from]
                        .receive(peers[from], decoded, now)
                        .unwrap();
                    for reply in replies {
                        if matches!(reply.message, Message::Want { .. }) {
                            engines[1 - from].send_finished(
                                reply.send_token(),
                                SendOutcome::HopAccepted,
                                now,
                            );
                        }
                        queues[1 - from].push_back(reply);
                    }
                }
            }
        }
        if engines[1].cache.get(manifest.id).unwrap().status == Status::Complete
            && engines[0]
                .cache
                .get(manifest.id)
                .unwrap()
                .completed_by
                .len()
                == 1
        {
            let mut actual = Vec::new();
            engines[1].cache.export(manifest.id, &mut actual).unwrap();
            assert_eq!(actual, bytes);
            assert_eq!(engines[1].diagnostics().received_blocks, 24);
            return (engines[1].diagnostics().retries, now);
        }
    }
    panic!("FIFO file and authenticated completion exceeded the original bound");
}

#[test]
fn contact_requests_fit_durable_fifo_without_duplicate_block_retries() {
    let (contact_retries, contact_seconds) = transfer(true, 4);
    let (larger_retries, larger_seconds) = transfer(false, 4);
    assert_eq!(contact_retries, 0);
    assert!(
        larger_retries > 0,
        "the larger window must expose the backlog"
    );
    assert!(contact_seconds < larger_seconds);
}

#[test]
fn contact_requests_leave_room_for_slow_durable_transport() {
    let (retries, _) = transfer(true, 7);
    assert_eq!(retries, 0);
}
