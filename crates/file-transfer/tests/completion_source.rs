use gcoms_file_transfer::swarm::*;
use std::io::Cursor;

const CHANNEL: [u8; 32] = [23; 32];
const SENDER: [u8; 32] = [1; 32];
const RECEIVER: [u8; 32] = [2; 32];

fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(dir.path(), true).unwrap();
    dir
}

fn cache(path: &std::path::Path) -> Cache {
    Cache::open(path, [31; 32], Default::default()).unwrap()
}

#[test]
fn authenticated_completion_discovers_a_source_for_a_retained_download() {
    let source_dir = directory();
    let target_dir = directory();
    let mut source = cache(source_dir.path());
    let bytes = vec![7; 2 * PIECE_BYTES];
    let manifest = source
        .import(
            [14; 16],
            Scope {
                channel: CHANNEL,
                participants: vec![],
            },
            "retained.bin".into(),
            bytes.len() as u64,
            &mut Cursor::new(bytes),
            1,
        )
        .unwrap();
    let mut target = cache(target_dir.path());
    target.offer(manifest.clone(), 2).unwrap();
    target.accept(manifest.id, 2).unwrap();
    let (proof, ciphertext) = source.read_piece(manifest.id, 0).unwrap();
    target.put(manifest.id, 0, &ciphertext, &proof, 3).unwrap();
    drop(target);
    let mut receiver = Engine::new(cache(target_dir.path()));
    receiver.set_members(CHANNEL, RECEIVER, [SENDER, RECEIVER]);
    receiver.tick(100).unwrap(); // Initial discovery is still outstanding.
    let peer = Peer {
        channel: CHANNEL,
        member: SENDER,
    };
    let complete = || Message::Complete {
        id: manifest.id,
        sha256: manifest.sha256,
    };
    let actions = receiver.receive(peer, complete(), 101).unwrap();
    assert_eq!(
        actions.len(),
        1,
        "authenticated completion must query its newly discovered source"
    );
    assert!(matches!(actions[0].message, Message::Inventory { id, start: 0 } if id == manifest.id));
    assert!(receiver.action_allowed(&actions[0]));
    let view = &receiver.views()[0];
    assert_eq!(view.sources, 1);
    assert_eq!(
        view.verified_sources, 0,
        "a completion claim is not verified data"
    );
    assert_eq!(view.state.status, Status::Downloading);
    assert_eq!(view.state.verified_bytes(), PIECE_BYTES as u64);
    assert!(
        receiver.receive(peer, complete(), 102).unwrap().is_empty(),
        "duplicate receipt must not accelerate polling"
    );
    assert!(
        receiver
            .tick(102)
            .unwrap()
            .iter()
            .all(|a| !matches!(a.message, Message::Want { .. })),
        "inventory is still required"
    );
    receiver
        .receive(
            peer,
            Message::Have {
                id: manifest.id,
                start: 0,
                pieces: vec![true, true],
            },
            103,
        )
        .unwrap();
    let wants = receiver.tick(103).unwrap();
    assert!(wants
        .iter()
        .any(|a| matches!(a.message, Message::Want { piece: 1, .. })));
    assert!(wants
        .iter()
        .all(|a| !matches!(a.message, Message::Want { piece: 0, .. })));
    receiver.clear_members();
    assert!(!receiver.action_allowed(&actions[0]));
    assert!(wants.iter().all(|a| !receiver.action_allowed(a)));
}

#[test]
fn completion_source_hints_preserve_scope_intent_and_poll_bounds() {
    let source_dir = directory();
    let mut source = cache(source_dir.path());
    let mut manifest = source
        .import(
            [15; 16],
            Scope {
                channel: CHANNEL,
                participants: vec![],
            },
            "bounded.bin".into(),
            1,
            &mut Cursor::new([7]),
            1,
        )
        .unwrap();
    for intent in [
        Status::Offered,
        Status::Paused,
        Status::Cancelled,
        Status::Downloading,
    ] {
        let target_dir = directory();
        let mut target = cache(target_dir.path());
        target.offer(manifest.clone(), 2).unwrap();
        if intent != Status::Offered {
            target.accept(manifest.id, 2).unwrap();
        }
        match intent {
            Status::Paused => target.pause(manifest.id).unwrap(),
            Status::Cancelled => target.cancel(manifest.id).unwrap(),
            _ => {}
        }
        let mut receiver = Engine::new(target);
        receiver.set_members(CHANNEL, RECEIVER, (1..=8).map(|n| [n; 32]));
        receiver.tick(100).unwrap();
        for (index, member) in [SENDER, [3; 32], [4; 32], [5; 32], [6; 32]]
            .into_iter()
            .enumerate()
        {
            let peer = Peer {
                channel: CHANNEL,
                member,
            };
            let actions = receiver
                .receive(
                    peer,
                    Message::Complete {
                        id: manifest.id,
                        sha256: manifest.sha256,
                    },
                    101,
                )
                .unwrap();
            assert_eq!(
                actions.len(),
                usize::from(intent == Status::Downloading && index < 4)
            );
        }
        assert_eq!(receiver.cache.get(manifest.id).unwrap().status, intent);
        assert_eq!(receiver.cache.get(manifest.id).unwrap().verified_bytes(), 0);
        assert_eq!(receiver.views()[0].verified_sources, 0);
    }
    // Channel membership alone does not grant access to a private share.
    manifest.scope.participants = vec![SENDER, RECEIVER];
    let target_dir = directory();
    let mut target = cache(target_dir.path());
    target.offer(manifest.clone(), 2).unwrap();
    target.accept(manifest.id, 2).unwrap();
    let mut receiver = Engine::new(target);
    receiver.set_members(CHANNEL, RECEIVER, [SENDER, RECEIVER, [3; 32]]);
    receiver.tick(100).unwrap();
    for (member, sha256) in [([3; 32], manifest.sha256), (SENDER, [0; 32])] {
        assert!(receiver
            .receive(
                Peer {
                    channel: CHANNEL,
                    member
                },
                Message::Complete {
                    id: manifest.id,
                    sha256
                },
                101
            )
            .is_err());
    }
    assert_eq!(receiver.views()[0].sources, 0);
    assert!(receiver
        .cache
        .get(manifest.id)
        .unwrap()
        .completed_by
        .is_empty());
    let peer = Peer {
        channel: CHANNEL,
        member: SENDER,
    };
    receiver
        .receive(
            peer,
            Message::Unavailable {
                id: manifest.id,
                request: [7; 16],
            },
            101,
        )
        .unwrap();
    assert!(
        receiver
            .receive(
                peer,
                Message::Complete {
                    id: manifest.id,
                    sha256: manifest.sha256
                },
                102
            )
            .unwrap()
            .is_empty(),
        "a receipt cannot bypass source backoff"
    );
}
