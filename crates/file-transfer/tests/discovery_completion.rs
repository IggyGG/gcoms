use gcoms_file_transfer::swarm::*;

#[test]
fn failed_discovery_obeys_existing_request_retry_bound() {
    let home = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(home.path(), true).unwrap();
    let cache = Cache::open(home.path(), [9; 32], Default::default()).unwrap();
    let mut engine = Engine::new(cache);
    engine.set_members([1; 32], [2; 32], [[2; 32], [3; 32]]);
    let actions = engine.tick(100).unwrap();
    let discover = actions
        .iter()
        .find(|a| matches!(a.message, Message::Discover { after: None }))
        .unwrap();
    let token = discover.send_token();
    engine.send_finished(token, SendOutcome::OutcomeUnknown, 101);
    assert!(engine.tick(130).unwrap().is_empty(), "no busy retry loop");
    assert!(
        engine
            .tick(131)
            .unwrap()
            .iter()
            .any(|a| matches!(a.message, Message::Discover { after: None })),
        "failed discovery must retry within the existing 30-second request bound"
    );
}

fn fixture() -> (tempfile::TempDir, Engine) {
    let home = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(home.path(), true).unwrap();
    let cache = Cache::open(home.path(), [9; 32], Default::default()).unwrap();
    let mut engine = Engine::new(cache);
    engine.set_members([1; 32], [2; 32], [[2; 32], [3; 32]]);
    (home, engine)
}

#[test]
fn discovery_keeps_healthy_cadence_and_never_duplicates_pending_attempts() {
    let (_home, mut engine) = fixture();
    let first = engine.tick(100).unwrap().remove(0);
    assert!(
        engine.tick(200).unwrap().is_empty(),
        "elapsed time is not send completion"
    );
    engine.send_finished(first.send_token(), SendOutcome::OutcomeUnknown, 200);
    assert!(engine.tick(229).unwrap().is_empty());
    let second = engine.tick(230).unwrap().remove(0);
    engine.send_finished(first.send_token(), SendOutcome::DefinitelyNotSent, 231);
    assert!(
        engine.tick(400).unwrap().is_empty(),
        "a stale token cannot release a newer attempt"
    );
    engine.send_finished(second.send_token(), SendOutcome::HopAccepted, 401);
    let third = engine.tick(402).unwrap().remove(0);
    engine.send_finished(third.send_token(), SendOutcome::HopAccepted, 403);
    assert!(engine.tick(461).unwrap().is_empty());
    assert_eq!(
        engine.tick(462).unwrap().len(),
        1,
        "healthy discovery retains its 60-second cadence"
    );
}

#[test]
fn revoked_and_readded_membership_cannot_reuse_discovery_completions() {
    let (_home, mut engine) = fixture();
    let first = engine.tick(100).unwrap().remove(0);
    engine.clear_members();
    engine.send_finished(first.send_token(), SendOutcome::OutcomeUnknown, 101);
    assert!(engine.tick(200).unwrap().is_empty());
    engine.set_members([1; 32], [2; 32], [[2; 32], [3; 32]]);
    let second = engine.tick(201).unwrap().remove(0);
    engine.send_finished(first.send_token(), SendOutcome::HopAccepted, 202);
    assert!(engine.tick(300).unwrap().is_empty());
    engine.send_finished(second.send_token(), SendOutcome::DefinitelyNotSent, 301);
    assert!(engine.tick(330).unwrap().is_empty());
    assert_eq!(engine.tick(331).unwrap().len(), 1);
}

#[test]
fn contact_discovery_covers_256_independent_conversations_without_raising_legacy_limit() {
    for (contact, expected) in [(true, 256), (false, 64)] {
        let home = tempfile::tempdir().unwrap();
        gcoms_private_fs::make_private(home.path(), true).unwrap();
        let cache = Cache::open(home.path(), [9; 32], Default::default()).unwrap();
        let mut engine = if contact {
            Engine::for_contacts(cache)
        } else {
            Engine::new(cache)
        };
        for n in 0u16..256 {
            let mut channel = [0; 32];
            channel[..2].copy_from_slice(&n.to_be_bytes());
            engine.set_members(channel, [1; 32], [[1; 32], [2; 32]]);
        }
        let mut discovered = std::collections::BTreeSet::new();
        // Same timestamp keeps maintenance retries out of this bounded discovery pass.
        for _ in 0..40 {
            let actions = engine.tick(100).unwrap();
            assert!(actions.len() <= 8);
            for action in actions {
                assert!(engine.action_allowed(&action));
                assert!(discovered.insert(action.peer.channel));
                engine.send_finished(action.send_token(), SendOutcome::HopAccepted, 100);
            }
        }
        assert_eq!(discovered.len(), expected);
    }
}
