use gcoms_file_transfer::swarm::*;
use std::{collections::VecDeque, io::Cursor};
fn temp() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(d.path(), true).unwrap();
    d
}
const CH: [u8; 32] = [9; 32];
fn scope() -> Scope {
    Scope {
        channel: CH,
        participants: vec![],
    }
}
fn cache(dir: &std::path::Path) -> Cache {
    Cache::open(dir, [7; 32], CacheConfig::default()).unwrap()
}
fn input(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}
fn imported(c: &mut Cache, n: usize) -> Manifest {
    c.import(
        [1; 16],
        scope(),
        "example.bin".into(),
        n as u64,
        &mut Cursor::new(input(n)),
        1,
    )
    .unwrap()
}
#[test]
fn import_restart_export_boundaries_and_ciphertext_at_rest() {
    for n in [
        0,
        1,
        PIECE_BYTES - 1,
        PIECE_BYTES,
        PIECE_BYTES + 1,
        3 * PIECE_BYTES,
    ] {
        let dir = temp();
        let mut c = cache(dir.path());
        let m = imported(&mut c, n);
        assert_eq!(c.get(m.id).unwrap().status, Status::Complete);
        let mut out = Vec::new();
        c.export(m.id, &mut out).unwrap();
        assert_eq!(out, input(n));
        let state = std::fs::read(dir.path().join(hex::encode(m.id)).join("state")).unwrap();
        assert!(!state.windows(m.name.len()).any(|s| s == m.name.as_bytes()));
        drop(c);
        let c = cache(dir.path());
        let mut out = Vec::new();
        c.export(m.id, &mut out).unwrap();
        assert_eq!(out, input(n));
    }
}
#[test]
fn sparse_resume_and_corruption_repair_preserve_good_pieces() {
    let a = temp();
    let b = temp();
    let mut source = cache(a.path());
    let m = imported(&mut source, 3 * PIECE_BYTES + 7);
    let mut target = cache(b.path());
    target.offer(m.clone(), 1).unwrap();
    target.accept(m.id, 1).unwrap();
    for i in [2, 0] {
        let (p, d) = source.read_piece(m.id, i).unwrap();
        target.put(m.id, i, &d, &p, 2).unwrap();
    }
    drop(target);
    let corrupt = b.path().join(hex::encode(m.id)).join("2.piece");
    let mut bytes = std::fs::read(&corrupt).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(corrupt, bytes).unwrap();
    let mut target = cache(b.path());
    assert_eq!(target.get(m.id).unwrap().have, [true, false, false, false]);
    target.accept(m.id, 3).unwrap();
    for i in [3, 2, 1] {
        let (p, d) = source.read_piece(m.id, i).unwrap();
        target.put(m.id, i, &d, &p, 4).unwrap();
    }
    let mut out = Vec::new();
    target.export(m.id, &mut out).unwrap();
    assert_eq!(out, input(3 * PIECE_BYTES + 7));
}
#[test]
fn proof_context_duplicates_and_manifest_conflicts() {
    let a = temp();
    let b = temp();
    let mut src = cache(a.path());
    let m = imported(&mut src, PIECE_BYTES + 1);
    let mut dst = cache(b.path());
    dst.offer(m.clone(), 1).unwrap();
    dst.accept(m.id, 1).unwrap();
    let (p, mut d) = src.read_piece(m.id, 0).unwrap();
    d[3] ^= 1;
    assert!(dst.put(m.id, 0, &d, &p, 2).is_err());
    d[3] ^= 1;
    assert!(dst.put(m.id, 0, &d, &p, 2).unwrap());
    assert!(!dst.put(m.id, 0, &d, &p, 2).unwrap());
    let mut conflicting = m.clone();
    conflicting.name = "other.bin".into();
    assert!(dst.offer(conflicting, 1).is_err());
    assert!(dst.put(m.id, 1, &d, &p, 2).is_err());
    dst.cancel(m.id).unwrap();
    assert!(dst.put(m.id, 0, &d, &p, 2).is_err());
    assert!(dst.read_piece(m.id, 0).is_err());
}
#[test]
fn import_is_resumable_and_never_reencrypts_changed_bytes() {
    let dir = temp();
    let mut c = cache(dir.path());
    c.begin_import(
        [1; 16],
        scope(),
        "source".into(),
        (PIECE_BYTES + 1) as u64,
        1,
    )
    .unwrap();
    c.import_piece([1; 16], 0, &input(PIECE_BYTES)).unwrap();
    drop(c);
    let mut c = cache(dir.path());
    assert_eq!(c.get([1; 16]).unwrap().status, Status::Importing);
    assert!(c.import_piece([1; 16], 0, &vec![0; PIECE_BYTES]).is_err());
    c.import_piece([1; 16], 0, &input(PIECE_BYTES)).unwrap();
    c.import_piece([1; 16], 1, &[42]).unwrap();
    c.finish_import([1; 16], 2).unwrap();
    assert_eq!(c.export_piece([1; 16], 1).unwrap(), [42]);
}
#[test]
fn codec_enforces_transport_budget_trailing_and_metadata_bounds() {
    let overflow = Message::Have {
        id: [1; 16],
        start: u32::MAX,
        pieces: vec![true],
    };
    assert!(Message::decode(&postcard::to_allocvec(&overflow).unwrap()).is_err());
    let m = Message::Data {
        id: [1; 16],
        piece: 1,
        offset: 0,
        request: [2; 16],
        proof: vec![[3; 32]; 16],
        bytes: vec![4; BLOCK_BYTES],
    };
    let mut bytes = m.encode().unwrap();
    assert!(bytes.len() < 12 * 1024 - CONTENT_TYPE.len() - 8);
    assert!(Message::decode(&bytes).is_ok());
    bytes.push(0);
    assert!(Message::decode(&bytes).is_err());
    assert!(Message::Data {
        id: [1; 16],
        piece: 1,
        offset: 0,
        request: [2; 16],
        proof: vec![],
        bytes: vec![4; BLOCK_BYTES + 1]
    }
    .encode()
    .is_err());
}
#[test]
fn quota_does_not_evict_active_and_expiry_releases_complete_files() {
    let a = temp();
    let mut src = cache(a.path());
    let m = imported(&mut src, PIECE_BYTES);
    let b = temp();
    let mut dst = Cache::open(
        b.path(),
        [7; 32],
        CacheConfig {
            quota_bytes: m.reservation() + 4096 + m.pieces() as u64 * 8,
            retention_secs: 2,
        },
    )
    .unwrap();
    dst.offer(m.clone(), 1).unwrap();
    dst.accept(m.id, 1).unwrap();
    let mut second = m.clone();
    second.id = [2; 16];
    dst.offer(second.clone(), 1).unwrap();
    assert!(dst.accept(second.id, 1).is_err());
    assert_eq!(dst.get(m.id).unwrap().status, Status::Downloading);
    let (p, d) = src.read_piece(m.id, 0).unwrap();
    dst.put(m.id, 0, &d, &p, 2).unwrap();
    dst.expire(4).unwrap();
    assert!(dst.get(m.id).is_err());
}
#[test]
fn private_multisource_late_join_after_sender_leaves_and_both_seeders_restart() {
    let dirs: Vec<_> = (0..4).map(|_| temp()).collect();
    let mut origin = cache(dirs[0].path());
    let m = imported(&mut origin, 5 * PIECE_BYTES + 17);
    for (i, dir) in dirs.iter().enumerate().take(3).skip(1) {
        let mut c = cache(dir.path());
        c.offer(m.clone(), 1).unwrap();
        c.accept(m.id, 1).unwrap();
        for piece in 0..m.pieces() as u32 {
            if piece as usize % 2 == i - 1 {
                let (p, d) = origin.read_piece(m.id, piece).unwrap();
                c.put(m.id, piece, &d, &p, 2).unwrap();
            }
        }
    }
    drop(origin); // no source has the entire file now
    let mut engines: Vec<_> = dirs
        .iter()
        .skip(1)
        .map(|d| Engine::new(cache(d.path())))
        .collect();
    for (i, e) in engines.iter_mut().enumerate() {
        e.set_members(CH, [(i + 2) as u8; 32], [[2; 32], [3; 32], [4; 32]]);
    }
    let mut queue = VecDeque::new();
    let mut delivered_sources = std::collections::BTreeSet::new();
    let mut accepted = false;
    for now in 10..300 {
        for (i, e) in engines.iter_mut().enumerate() {
            for action in e.tick(now).unwrap() {
                queue.push_back((i, action));
            }
        }
        let mut iterations = 0;
        while let Some((from, action)) = queue.pop_front() {
            engines[from].send_finished(action.send_token(), SendOutcome::HopAccepted, now);
            iterations += 1;
            assert!(iterations < 10000);
            let to = action.peer.member[0] as usize - 2;
            // Drop and duplicate a bounded selection of packets to exercise timers.
            if now == 10 && matches!(action.message, Message::Data { offset: 0, .. }) {
                continue;
            }
            if matches!(action.message, Message::Data { .. }) && to == 2 {
                delivered_sources.insert(from);
            }
            let wire = action.message.encode().unwrap();
            let message = Message::decode(&wire).unwrap();
            let replies = engines[to]
                .receive(
                    Peer {
                        channel: CH,
                        member: [(from + 2) as u8; 32],
                    },
                    message,
                    now,
                )
                .unwrap();
            for reply in replies {
                queue.push_back((to, reply));
            }
        }
        if !accepted && engines[2].cache.get(m.id).is_ok() {
            engines[2].accept(m.id, now).unwrap();
            accepted = true;
        }
        assert!(engines.iter().all(|e| e.buffered_bytes() < 4 * 1024 * 1024));
        if engines[2]
            .cache
            .get(m.id)
            .is_ok_and(|s| s.status == Status::Complete)
        {
            break;
        }
    }
    assert!(accepted);
    assert_eq!(delivered_sources.len(), 2);
    assert_eq!(
        engines[2]
            .views()
            .iter()
            .find(|v| v.state.manifest.id == m.id)
            .unwrap()
            .verified_sources,
        2
    );
    let mut out = Vec::new();
    engines[2].cache.export(m.id, &mut out).unwrap();
    assert_eq!(out, input(5 * PIECE_BYTES + 17));
    engines[0].set_members(CH, [2; 32], [[2; 32], [3; 32]]);
    assert!(engines[0]
        .receive(
            Peer {
                channel: CH,
                member: [4; 32]
            },
            Message::Inventory { id: m.id, start: 0 },
            400
        )
        .is_err());
}

#[test]
fn block_window_reorders_deduplicates_and_retries_only_missing_offsets_after_send_completion() {
    let source_dir = temp();
    let receiver_dir = temp();
    let mut source_cache = cache(source_dir.path());
    let manifest = imported(&mut source_cache, PIECE_BYTES);
    let mut source = Engine::new(source_cache);
    let mut receiver = Engine::new(cache(receiver_dir.path()));
    source.set_members(CH, [1; 32], [[1; 32], [2; 32]]);
    receiver.set_members(CH, [2; 32], [[1; 32], [2; 32]]);
    let peer = Peer {
        channel: CH,
        member: [1; 32],
    };
    let target = Peer {
        channel: CH,
        member: [2; 32],
    };
    receiver
        .receive(
            peer,
            Message::Offers {
                manifests: vec![manifest.clone()],
                next: None,
            },
            1,
        )
        .unwrap();
    receiver.accept(manifest.id, 1).unwrap();
    receiver
        .receive(
            peer,
            Message::Have {
                id: manifest.id,
                start: 0,
                pieces: vec![true],
            },
            1,
        )
        .unwrap();
    let mut wants: Vec<_> = receiver
        .tick(2)
        .unwrap()
        .into_iter()
        .filter(|a| matches!(a.message, Message::Want { .. }))
        .collect();
    assert_eq!(wants.len(), BLOCK_WINDOW);
    // A delayed local receipt cannot cause overlapping attempts.
    assert!(!receiver
        .tick(100)
        .unwrap()
        .iter()
        .any(|a| matches!(a.message, Message::Want { .. })));
    for action in &wants {
        receiver.send_finished(action.send_token(), SendOutcome::HopAccepted, 100);
    }
    let first = wants.remove(0);
    let mut next = VecDeque::new();
    for action in wants.into_iter().rev() {
        let data = source
            .receive(target, action.message, 101)
            .unwrap()
            .pop()
            .unwrap();
        let duplicate = data.message.clone();
        next.extend(receiver.receive(peer, data.message, 101).unwrap());
        assert!(receiver.receive(peer, duplicate, 101).unwrap().is_empty());
    }
    let retries: Vec<_> = receiver
        .tick(130)
        .unwrap()
        .into_iter()
        .filter(|a| matches!(a.message, Message::Want { .. }))
        .collect();
    assert_eq!(retries.len(), 1);
    assert!(matches!(
        retries[0].message,
        Message::Want { offset: 0, .. }
    ));
    assert_eq!(
        receiver.diagnostics().received_blocks,
        (BLOCK_WINDOW - 1) as u64
    );
    next.push_back(first); // an original late response remains valid
    while let Some(action) = next.pop_front() {
        if !matches!(action.message, Message::Want { .. }) {
            continue;
        }
        receiver.send_finished(action.send_token(), SendOutcome::HopAccepted, 131);
        for data in source.receive(target, action.message, 131).unwrap() {
            next.extend(receiver.receive(peer, data.message, 131).unwrap());
        }
    }
    assert_eq!(
        receiver.cache.get(manifest.id).unwrap().status,
        Status::Complete
    );
    let mut exported = Vec::new();
    receiver.cache.export(manifest.id, &mut exported).unwrap();
    assert_eq!(exported, input(PIECE_BYTES));
}

#[test]
fn queued_payload_copies_are_reserved_before_allocation_and_released_on_drop() {
    let dir = temp();
    let mut source_cache = cache(dir.path());
    let manifest = imported(&mut source_cache, PIECE_BYTES);
    let mut source = Engine::new(source_cache);
    source.set_members(CH, [1; 32], [[1; 32], [2; 32]]);
    let peer = Peer {
        channel: CH,
        member: [2; 32],
    };
    let want = || Message::Want {
        id: manifest.id,
        piece: 0,
        offset: 0,
        request: [9; 16],
    };
    let mut pending = Vec::new();
    loop {
        let actions = source.receive(peer, want(), 2).unwrap();
        if actions.is_empty() {
            break;
        }
        pending.extend(actions);
        assert!(source.buffered_bytes() <= PAYLOAD_BUDGET);
        assert!(pending.len() < 128);
    }
    assert!(!pending.is_empty());
    let guards: Vec<_> = pending.iter().filter_map(Action::payload_guard).collect();
    let reserved = source.buffered_bytes();
    drop(pending);
    assert_eq!(source.buffered_bytes(), reserved);
    drop(guards);
    assert!(source.buffered_bytes() < reserved);
    assert_eq!(source.receive(peer, want(), 3).unwrap().len(), 1);
}
#[test]
fn pm_scope_does_not_expand_to_channel_members() {
    let dir = temp();
    let mut e = Engine::new(cache(dir.path()));
    e.set_members(CH, [2; 32], [[2; 32], [3; 32], [4; 32]]);
    let scoped = Scope {
        channel: CH,
        participants: vec![[2; 32], [3; 32]],
    };
    assert!(e.permits(
        Peer {
            channel: CH,
            member: [3; 32]
        },
        &scoped
    ));
    assert!(!e.permits(
        Peer {
            channel: CH,
            member: [4; 32]
        },
        &scoped
    ));
}

#[test]
fn source_crash_before_journal_and_receipts_survive_reopen() {
    let dir = temp();
    let mut c = cache(dir.path());
    c.begin_import([1; 16], scope(), "source".into(), 1, 1)
        .unwrap();
    let journal = dir.path().join(hex::encode([1; 16])).join("state");
    let before = std::fs::read(&journal).unwrap();
    let abandoned = journal.parent().unwrap().join(".stage-interrupted");
    std::fs::write(&abandoned, b"unpublished ciphertext").unwrap();
    gcoms_private_fs::make_private(&abandoned, false).unwrap();
    c.import_piece([1; 16], 0, &[42]).unwrap();
    drop(c);
    // Piece rename persisted, but the durable progress-bit rename did not.
    std::fs::write(&journal, before).unwrap();
    let mut c = cache(dir.path());
    assert!(!abandoned.exists());
    assert!(!c.get([1; 16]).unwrap().have[0]);
    assert!(c.import_piece([1; 16], 0, &[43]).is_err());
    c.import_piece([1; 16], 0, &[42]).unwrap();
    c.finish_import([1; 16], 2).unwrap();
    c.receipt([1; 16], [3; 32]).unwrap();
    c.receipt([1; 16], [3; 32]).unwrap();
    drop(c);
    assert_eq!(
        cache(dir.path()).get([1; 16]).unwrap().completed_by,
        vec![[3; 32]]
    );
}

#[test]
fn queued_data_is_denied_after_cancel_and_membership_revocation() {
    let dir = temp();
    let mut c = cache(dir.path());
    let m = imported(&mut c, 1);
    let mut engine = Engine::new(c);
    engine.set_members(CH, [1; 32], [[1; 32], [2; 32]]);
    let peer = Peer {
        channel: CH,
        member: [2; 32],
    };
    let action = engine
        .receive(
            peer,
            Message::Want {
                id: m.id,
                piece: 0,
                offset: 0,
                request: [4; 16],
            },
            3,
        )
        .unwrap()
        .remove(0);
    assert!(engine.action_allowed(&action));
    engine.set_members(CH, [1; 32], [[1; 32]]);
    assert!(!engine.action_allowed(&action));
    engine.set_members(CH, [1; 32], [[1; 32], [2; 32]]);
    engine.cancel(m.id).unwrap();
    assert!(!engine.action_allowed(&action));
}

#[test]
#[ignore = "release qualification: writes and verifies a 1 GiB cache"]
fn gib_import_resume_export_is_streaming() {
    struct Pattern {
        remaining: u64,
        offset: u64,
    }
    impl std::io::Read for Pattern {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let n = self.remaining.min(out.len() as u64) as usize;
            for (i, b) in out[..n].iter_mut().enumerate() {
                *b = ((self.offset + i as u64) % 251) as u8;
            }
            self.offset += n as u64;
            self.remaining -= n as u64;
            Ok(n)
        }
    }
    struct Verify {
        count: u64,
    }
    impl std::io::Write for Verify {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            for (i, b) in bytes.iter().enumerate() {
                assert_eq!(*b, ((self.count + i as u64) % 251) as u8);
            }
            self.count += bytes.len() as u64;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let size = 1024 * 1024 * 1024;
    let dir = temp();
    let mut c = cache(dir.path());
    let m = c
        .import(
            [1; 16],
            scope(),
            "large.bin".into(),
            size,
            &mut Pattern {
                remaining: size,
                offset: 0,
            },
            1,
        )
        .unwrap();
    assert_eq!(m.pieces(), 4096);
    drop(c);
    let c = cache(dir.path());
    let mut output = Verify { count: 0 };
    c.export(m.id, &mut output).unwrap();
    assert_eq!(output.count, size);
    assert!(c.used() < size + 8 * 1024 * 1024);
}

#[test]
fn later_sources_are_discovered_and_bad_sources_are_replaced() {
    let a = temp();
    let b = temp();
    let mut src = cache(a.path());
    let m = imported(&mut src, 1);
    let mut receiver = Engine::new(cache(b.path()));
    receiver.set_members(CH, [9; 32], (1..=9).map(|n| [n; 32]));
    for n in 1..=6 {
        receiver
            .receive(
                Peer {
                    channel: CH,
                    member: [n; 32],
                },
                Message::Offers {
                    manifests: vec![m.clone()],
                    next: None,
                },
                1,
            )
            .unwrap();
    }
    receiver.accept(m.id, 1).unwrap();
    let initial = receiver.tick(1).unwrap();
    assert!(!initial
        .iter()
        .any(|a| a.peer.member == [5; 32] && matches!(a.message, Message::Inventory { .. })));
    let rotated = receiver.tick(32).unwrap();
    assert!(rotated
        .iter()
        .any(|a| a.peer.member == [5; 32] && matches!(a.message, Message::Inventory { .. })));
    for n in [5, 6] {
        receiver
            .receive(
                Peer {
                    channel: CH,
                    member: [n; 32],
                },
                Message::Have {
                    id: m.id,
                    start: 0,
                    pieces: vec![true],
                },
                32,
            )
            .unwrap();
    }
    let request = receiver
        .tick(33)
        .unwrap()
        .into_iter()
        .find(|a| matches!(a.message, Message::Want { .. }))
        .unwrap();
    assert_eq!(request.peer.member, [5; 32]);
    let Message::Want { request: token, .. } = request.message else {
        unreachable!()
    };
    let (proof, bytes) = src.read_piece(m.id, 0).unwrap();
    let mut bad = bytes.clone();
    bad[0] ^= 1;
    assert!(receiver
        .receive(
            request.peer,
            Message::Data {
                id: m.id,
                piece: 0,
                offset: 0,
                request: token,
                proof: proof.clone(),
                bytes: bad
            },
            33
        )
        .is_err());
    let request = receiver
        .tick(34)
        .unwrap()
        .into_iter()
        .find(|a| matches!(a.message, Message::Want { .. }))
        .unwrap();
    assert_eq!(request.peer.member, [6; 32]);
    let Message::Want { request: token, .. } = request.message else {
        unreachable!()
    };
    receiver
        .receive(
            request.peer,
            Message::Data {
                id: m.id,
                piece: 0,
                offset: 0,
                request: token,
                proof,
                bytes,
            },
            34,
        )
        .unwrap();
    assert_eq!(receiver.cache.get(m.id).unwrap().status, Status::Complete);
}

#[test]
fn revoked_downloads_release_slots_and_remain_locally_manageable() {
    let a = temp();
    let b = temp();
    let mut src = cache(a.path());
    let m = imported(&mut src, 1);
    let mut e = Engine::new(cache(b.path()));
    e.set_members(CH, [1; 32], [[1; 32], [2; 32]]);
    for n in [1, 2] {
        let mut m = m.clone();
        m.id = [n; 16];
        e.cache.offer(m, 1).unwrap();
        e.accept([n; 16], 1).unwrap();
    }
    e.set_members(CH, [1; 32], []);
    assert!(e.tick(2).unwrap().is_empty());
    assert!(e.views().iter().all(|v| v.state.status == Status::Paused));
    e.cancel([1; 16]).unwrap();
    let next = [8; 32];
    e.set_members(next, [1; 32], [[1; 32], [2; 32]]);
    let mut m = m.clone();
    m.id = [3; 16];
    m.scope.channel = next;
    e.cache.offer(m, 3).unwrap();
    e.accept([3; 16], 3).unwrap();
}
