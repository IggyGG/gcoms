use gcoms_file_transfer::swarm::*;
use std::{
    collections::{BTreeSet, VecDeque},
    io::Cursor,
};

const CHANNEL: [u8; 32] = [23; 32];
const SENDER: [u8; 32] = [1; 32];
const RECEIVER: [u8; 32] = [2; 32];

fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(dir.path(), true).unwrap();
    dir
}

fn cache(dir: &std::path::Path) -> Cache {
    Cache::open(dir, [31; 32], CacheConfig::default()).unwrap()
}

#[test]
fn overnight_restart_waits_for_membership_then_requests_only_missing_pieces() {
    let source_dir = directory();
    let target_dir = directory();
    let bytes: Vec<_> = (0..5 * PIECE_BYTES).map(|i| (i % 251) as u8).collect();
    let mut source = cache(source_dir.path());
    let manifest = source
        .import(
            [11; 16],
            Scope {
                channel: CHANNEL,
                participants: vec![],
            },
            "interrupted.bin".into(),
            bytes.len() as u64,
            &mut Cursor::new(&bytes),
            1,
        )
        .unwrap();
    let mut target = cache(target_dir.path());
    target.offer(manifest.clone(), 2).unwrap();
    target.accept(manifest.id, 2).unwrap();
    for piece in [0, 1, 3, 4] {
        let (proof, ciphertext) = source.read_piece(manifest.id, piece).unwrap();
        target
            .put(manifest.id, piece, &ciphertext, &proof, 3)
            .unwrap();
    }
    assert_eq!(
        target.get(manifest.id).unwrap().verified_bytes(),
        bytes.len() as u64 * 4 / 5
    );
    drop(source);
    drop(target);

    let mut engines = [
        Engine::new(cache(source_dir.path())),
        Engine::new(cache(target_dir.path())),
    ];
    for now in [86_400, 86_401, 86_430] {
        assert!(engines[1].tick(now).unwrap().is_empty());
        assert_eq!(
            engines[1].cache.get(manifest.id).unwrap().status,
            Status::Downloading,
            "loading channel membership must not discard the user's download intent"
        );
    }
    engines[0].set_members(CHANNEL, SENDER, [SENDER, RECEIVER]);
    engines[1].set_members(CHANNEL, RECEIVER, [SENDER, RECEIVER]);
    let mut requested = BTreeSet::new();
    for now in 86_431..86_600 {
        let mut queue = VecDeque::new();
        for (from, engine) in engines.iter_mut().enumerate() {
            queue.extend(engine.tick(now).unwrap().into_iter().map(|a| (from, a)));
        }
        let mut deliveries = 0;
        while let Some((from, action)) = queue.pop_front() {
            deliveries += 1;
            assert!(deliveries < 10_000);
            assert!(engines[from].action_allowed(&action));
            if from == 1 {
                if let Message::Want { piece, .. } = &action.message {
                    requested.insert(*piece);
                }
            }
            engines[from].send_finished(action.send_token(), SendOutcome::HopAccepted, now);
            let to = 1 - from;
            let message = Message::decode(&action.message.encode().unwrap()).unwrap();
            let replies = engines[to]
                .receive(
                    Peer {
                        channel: CHANNEL,
                        member: if from == 0 { SENDER } else { RECEIVER },
                    },
                    message,
                    now,
                )
                .unwrap();
            queue.extend(replies.into_iter().map(|a| (to, a)));
        }
        if engines[1].cache.get(manifest.id).unwrap().status == Status::Complete {
            break;
        }
    }
    assert_eq!(requested, BTreeSet::from([2]));
    let mut output = Vec::new();
    engines[1].cache.export(manifest.id, &mut output).unwrap();
    assert_eq!(output, bytes);
}

#[test]
fn recovery_preserves_user_pauses_cancellation_and_unaccepted_offers() {
    let source_dir = directory();
    let mut source = cache(source_dir.path());
    let manifest = source
        .import(
            [12; 16],
            Scope {
                channel: CHANNEL,
                participants: vec![],
            },
            "intent.bin".into(),
            1,
            &mut Cursor::new([7]),
            1,
        )
        .unwrap();
    for (mode, expected) in [
        ("offered", Status::Offered),
        ("paused", Status::Paused),
        ("cancelled", Status::Cancelled),
        ("failure", Status::Paused),
        ("legacy-wait", Status::Downloading),
        ("legacy-explicit-pause", Status::Paused),
    ] {
        let dir = directory();
        let mut target = cache(dir.path());
        target.offer(manifest.clone(), 2).unwrap();
        if mode != "offered" {
            target.accept(manifest.id, 2).unwrap();
        }
        match mode {
            "paused" => target.pause(manifest.id).unwrap(),
            "cancelled" => target.cancel(manifest.id).unwrap(),
            "failure" => target
                .failure(manifest.id, "Could not retain piece: disk full".into())
                .unwrap(),
            "legacy-wait" | "legacy-explicit-pause" => {
                target
                    .failure(
                        manifest.id,
                        "Conversation membership unavailable; transfer paused".into(),
                    )
                    .unwrap();
                if mode == "legacy-explicit-pause" {
                    target.pause(manifest.id).unwrap();
                }
            }
            _ => {}
        }
        drop(target);
        let mut engine = Engine::new(cache(dir.path()));
        assert!(engine.tick(86_400).unwrap().is_empty());
        assert_eq!(
            engine.cache.get(manifest.id).unwrap().status,
            expected,
            "{mode}"
        );
        engine.set_members(CHANNEL, RECEIVER, [SENDER, RECEIVER]);
        engine.tick(86_401).unwrap();
        assert_eq!(
            engine.cache.get(manifest.id).unwrap().status,
            expected,
            "{mode}"
        );
        drop(engine);
        assert_eq!(
            cache(dir.path()).get(manifest.id).unwrap().status,
            expected,
            "persisted {mode}"
        );
    }
}

#[test]
fn waiting_download_cannot_request_or_accept_data_without_current_scope() {
    let source_dir = directory();
    let target_dir = directory();
    let mut source = cache(source_dir.path());
    let manifest = source
        .import(
            [13; 16],
            Scope {
                channel: CHANNEL,
                participants: vec![SENDER, RECEIVER],
            },
            "private.bin".into(),
            1,
            &mut Cursor::new([7]),
            1,
        )
        .unwrap();
    let mut sender = Engine::new(source);
    let mut receiver = Engine::new(cache(target_dir.path()));
    sender.set_members(CHANNEL, SENDER, [SENDER, RECEIVER]);
    receiver.set_members(CHANNEL, RECEIVER, [SENDER, RECEIVER]);
    let from_sender = Peer {
        channel: CHANNEL,
        member: SENDER,
    };
    receiver
        .receive(
            from_sender,
            Message::Offers {
                manifests: vec![manifest.clone()],
                next: None,
            },
            2,
        )
        .unwrap();
    receiver.accept(manifest.id, 2).unwrap();
    receiver
        .receive(
            from_sender,
            Message::Have {
                id: manifest.id,
                start: 0,
                pieces: vec![true],
            },
            2,
        )
        .unwrap();
    let want = receiver
        .tick(3)
        .unwrap()
        .into_iter()
        .find(|a| matches!(a.message, Message::Want { .. }))
        .unwrap();
    assert!(receiver.action_allowed(&want));
    let data = sender
        .receive(
            Peer {
                channel: CHANNEL,
                member: RECEIVER,
            },
            Message::decode(&want.message.encode().unwrap()).unwrap(),
            3,
        )
        .unwrap()
        .remove(0);
    // The sender still belongs, but our membership is no longer available.
    receiver.set_members(CHANNEL, RECEIVER, [SENDER]);
    assert!(!receiver.action_allowed(&want));
    assert!(receiver
        .receive(
            from_sender,
            Message::decode(&data.message.encode().unwrap()).unwrap(),
            4
        )
        .is_err());
    assert!(receiver
        .tick(4)
        .unwrap()
        .iter()
        .all(|a| !matches!(a.message, Message::Want { .. } | Message::Inventory { .. })));
    assert_eq!(receiver.cache.get(manifest.id).unwrap().verified_bytes(), 0);
    assert_eq!(
        receiver.cache.get(manifest.id).unwrap().status,
        Status::Downloading
    );
    assert!(receiver.views()[0].waiting_for_peers);
    receiver.set_members(CHANNEL, RECEIVER, [SENDER, RECEIVER]);
    receiver
        .receive(
            from_sender,
            Message::Have {
                id: manifest.id,
                start: 0,
                pieces: vec![true],
            },
            5,
        )
        .unwrap();
    assert!(receiver
        .tick(5)
        .unwrap()
        .iter()
        .any(|a| matches!(a.message, Message::Want { .. })));
}
