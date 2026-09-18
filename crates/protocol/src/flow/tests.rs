use super::*;
use gcoms_crypto::{
    initiate_authenticated, split_authenticated_payload, verify_first_move_auth, Frame,
    IdentityKeypair, Session, SessionContext,
};
use rand::{rngs::StdRng, SeedableRng};

struct Endpoint {
    ratchet: Session,
    flow: Window,
    context: SessionContext,
    rng: StdRng,
}

impl Endpoint {
    fn send(&mut self, purpose: Purpose, body: &[u8]) -> Result<Frame, Error> {
        let counter = self.flow.next_counter(purpose)?;
        let record = Record::new(purpose, 1000, body, &mut self.rng)?;
        let prepared = self
            .ratchet
            .prepare_send(&record.encode(), &[7; 32], &self.context)
            .unwrap();
        let frame = Frame::decode(prepared.wire()).unwrap();
        assert_eq!(frame.ctr, counter);
        let mut staged = self.flow.clone();
        staged.record_sent(counter, prepared.wire(), &record, 100)?;
        // Simulate one durable transaction containing both state snapshots.
        let restored =
            Session::open_state(prepared.sealed_state(), &[7; 32], &self.context).unwrap();
        let restored_flow = Window::decode_private(&staged.encode_private())?;
        assert_eq!(restored.send_ctr(), restored_flow.sent_counter());
        self.ratchet.commit_send(prepared).unwrap();
        self.flow = restored_flow;
        Ok(frame)
    }

    fn receive(&mut self, frame: &Frame) -> [u8; CREDIT_BYTES] {
        let packet = frame.encode();
        let prepared = self
            .ratchet
            .prepare_receive(frame, &[7; 32], &self.context)
            .unwrap();
        let record = Record::decode(prepared.plaintext()).unwrap();
        let mut staged = self.flow.clone();
        staged
            .record_authenticated(frame.ctr, &packet, &record)
            .unwrap();
        let credit = staged.credit_for_duplicate(frame.ctr, &packet).unwrap();
        // A receipt becomes visible only after successful persistence of both.
        let restored =
            Session::open_state(prepared.sealed_state(), &[7; 32], &self.context).unwrap();
        let restored_flow = Window::decode_private(&staged.encode_private()).unwrap();
        assert_eq!(
            restored.recv_ctr(),
            restored_flow.received.highest().unwrap()
        );
        self.ratchet.commit_receive(prepared).unwrap();
        self.flow = restored_flow;
        credit
    }

    fn reload(&mut self) {
        let sealed = self.ratchet.seal_state(&[7; 32], &self.context).unwrap();
        self.ratchet = Session::open_state(&sealed, &[7; 32], &self.context).unwrap();
        self.flow = Window::decode_private(&self.flow.encode_private()).unwrap();
    }
}

fn pair() -> (Endpoint, Endpoint) {
    let alice = IdentityKeypair::from_seed([1; 32]);
    let bob = IdentityKeypair::from_seed([2; 32]);
    let (bundle, secrets) = bob.issue_bundle();
    let mut rng = StdRng::seed_from_u64(1);
    let hello = Record::new(Purpose::Control, 0, b"GC2 session", &mut rng).unwrap();
    let (first, a) =
        initiate_authenticated(&alice, &bob.public_bytes(), &bundle, &hello.encode()).unwrap();
    let (plaintext, b) = secrets.accept(&first).unwrap();
    let (body, signature) = split_authenticated_payload(&plaintext).unwrap();
    assert!(verify_first_move_auth(
        &first,
        &alice.public_bytes(),
        &bob.public_bytes(),
        &bundle,
        body,
        signature
    ));
    let decoded = Record::decode(body).unwrap();
    let mut aw = Window::new([3; 16]).unwrap();
    let mut bw = Window::new([3; 16]).unwrap();
    aw.record_sent(1, &first.encode(), &hello, 100).unwrap();
    bw.record_authenticated(1, &first.encode(), &decoded)
        .unwrap();
    let receipt = bw.credit_for_duplicate(1, &first.encode()).unwrap();
    assert!(aw.accept_credit(&receipt).unwrap());
    assert_eq!(aw.credited_floor(), 1);
    assert_eq!(bw.received_floor(), 1);
    let make = |ratchet, flow, peer: &[u8]| Endpoint {
        ratchet,
        flow,
        context: SessionContext::new(b"test", b"gc2", peer, b"conversation").unwrap(),
        rng: StdRng::seed_from_u64(5),
    };
    (make(a, aw, b"alice"), make(b, bw, b"bob"))
}

#[test]
fn volatile_retry_bytes_stay_in_ram_and_restore_requires_recovery_or_credit() {
    let (a, b) = pair();
    let mut sender = CreditedSession::from_authenticated(a.ratchet, a.flow).unwrap();
    let mut receiver = CreditedSession::from_authenticated(b.ratchet, b.flow).unwrap();
    let body = b"RAM-only media bytes which must never appear in the private flow archive";
    let record = Record::new(Purpose::Interactive, 1000, body, &mut rand::rngs::OsRng).unwrap();
    let prepared = sender
        .prepare_volatile_send(&record, 100, &[7; 32], &a.context)
        .unwrap();
    let frame = Frame::decode(prepared.wire()).unwrap();
    let packet = crate::gc2_session::encode_frame(sender.window().session(), &frame).unwrap();
    let private = prepared.private_flow();
    assert_eq!(&private[..5], b"GCW2\x03");
    assert!(!private.windows(body.len()).any(|part| part == body));
    assert!(!private.windows(packet.len()).any(|part| part == packet));
    let mut restored =
        CreditedSession::restore(prepared.sealed_ratchet(), &private, &[7; 32], &a.context)
            .unwrap();
    assert_eq!(restored.window().cached_payload_count(), 0);
    assert_eq!(restored.window().cached_payload_bytes(), 0);
    assert_eq!(restored.window().retries().count(), 0);
    assert!(restored.window().recovery_required(100));
    assert!(matches!(
        restored.prepare_send(&record, 100, &[7; 32], &a.context),
        Err(SessionError::RecoveryRequired),
    ));
    assert_eq!(prepared.cached_payload_bytes(), packet.len());
    sender.commit_send(prepared).unwrap();
    assert_eq!(sender.window().retries().next().unwrap().2, packet);
    assert!(!sender.window().recovery_required(100));
    // A receive/ACK transaction must preserve the live RAM-only retry buffer.
    let reply = Record::new(Purpose::Control, 0, b"reply", &mut rand::rngs::OsRng).unwrap();
    let reply = receiver
        .prepare_send(&reply, 100, &[7; 32], &b.context)
        .unwrap();
    let reply_frame = Frame::decode(reply.wire()).unwrap();
    receiver.commit_send(reply).unwrap();
    let received = sender
        .prepare_receive(&reply_frame, &[7; 32], &a.context)
        .unwrap();
    let staged = sender
        .stage_received(&received, &[7; 32], &a.context)
        .unwrap();
    assert_eq!(staged.window().retries().next().unwrap().2, packet);
    let received = receiver
        .prepare_receive(&frame, &[7; 32], &b.context)
        .unwrap();
    assert_eq!(received.record().unwrap().body(), body);
    let credit = *received.credit();
    receiver.commit_receive(received).unwrap();
    // A retained authority can authenticate proof that the missing RAM packet
    // arrived, without reconstructing its body or consuming a new counter.
    let received = restored.prepare_credit(&credit).unwrap().unwrap();
    restored.commit_credit(received).unwrap();
    assert!(!restored.window().recovery_required(100));
    assert!(restored
        .prepare_send(&record, 100, &[7; 32], &a.context)
        .is_ok());
    assert_eq!(&restored.window().encode_private()[..5], b"GCW2\x01");
}

#[test]
fn selectively_credited_volatile_counter_does_not_hide_a_durable_repair() {
    let (a, b) = pair();
    let mut sender = CreditedSession::from_authenticated(a.ratchet, a.flow).unwrap();
    let mut receiver = CreditedSession::from_authenticated(b.ratchet, b.flow).unwrap();
    let durable = Record::new(
        Purpose::Bulk,
        1000,
        b"retained file piece",
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    let volatile = Record::new(
        Purpose::Interactive,
        1000,
        b"ephemeral",
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    let prepared = sender
        .prepare_send(&durable, 100, &[7; 32], &a.context)
        .unwrap();
    let first = Frame::decode(prepared.wire()).unwrap();
    sender.commit_send(prepared).unwrap();
    let prepared = sender
        .prepare_volatile_send(&volatile, 100, &[7; 32], &a.context)
        .unwrap();
    let second = Frame::decode(prepared.wire()).unwrap();
    sender.commit_send(prepared).unwrap();
    let received = receiver
        .prepare_receive(&second, &[7; 32], &b.context)
        .unwrap();
    let credit = *received.credit();
    receiver.commit_receive(received).unwrap();
    let credit = sender.prepare_credit(&credit).unwrap().unwrap();
    sender.commit_credit(credit).unwrap();
    let ratchet = sender.seal_ratchet(&[7; 32], &a.context).unwrap();
    let mut restored = CreditedSession::restore(
        &ratchet,
        &sender.window().encode_private(),
        &[7; 32],
        &a.context,
    )
    .unwrap();
    assert_eq!(restored.window().cached_payload_count(), 1);
    assert!(!restored.window().recovery_required(100));
    assert_eq!(restored.window().retries().next().unwrap().0, first.ctr);
    let received = receiver
        .prepare_receive(&first, &[7; 32], &b.context)
        .unwrap();
    let credit = *received.credit();
    receiver.commit_receive(received).unwrap();
    let credit = restored.prepare_credit(&credit).unwrap().unwrap();
    restored.commit_credit(credit).unwrap();
    assert_eq!(restored.window().credited_floor(), second.ctr);
    assert_eq!(restored.window().cached_payload_count(), 0);
}

#[test]
fn volatile_archives_reject_control_records_bad_markers_and_noncanonical_versions() {
    let (a, _) = pair();
    let sender = CreditedSession::from_authenticated(a.ratchet, a.flow).unwrap();
    let control = Record::new(Purpose::Control, 0, b"ack", &mut rand::rngs::OsRng).unwrap();
    assert!(sender
        .prepare_volatile_send(&control, 100, &[7; 32], &a.context)
        .is_err());
    let media = Record::new(Purpose::Interactive, 1000, b"media", &mut rand::rngs::OsRng).unwrap();
    let prepared = sender
        .prepare_volatile_send(&media, 100, &[7; 32], &a.context)
        .unwrap();
    let bytes = prepared.private_flow();
    assert_eq!(
        Window::decode_private(&bytes).unwrap().encode_private(),
        bytes
    );
    for (offset, value) in [(4, 4), (70, Purpose::Control as u8), (111, 2)] {
        let mut bad = bytes.to_vec();
        bad[offset] = value;
        assert!(Window::decode_private(&bad).is_err(), "offset {offset}");
    }
    let mut bad = bytes.to_vec();
    bad[21..29].fill(0);
    assert!(Window::decode_private(&bad).is_err());
    for end in 0..bytes.len() {
        assert!(Window::decode_private(&bytes[..end]).is_err());
    }
    let mut bad = bytes.to_vec();
    bad.push(0);
    assert!(Window::decode_private(&bad).is_err());
}

#[test]
fn a_lost_counter_blocks_credit_until_exact_ciphertext_repairs_it() {
    let (mut a, mut b) = pair();
    a.ratchet
        .set_pq_policy(7, std::time::Duration::from_secs(3600));
    let mut frames = Vec::new();
    for index in 0..COUNTER_WINDOW {
        if index == 20 {
            let reply = b.send(Purpose::Control, b"rotate DH epoch").unwrap();
            b.flow.accept_credit(&a.receive(&reply)).unwrap();
        }
        frames.push(a.send(Purpose::Control, b"payload").unwrap());
    }
    assert_eq!(
        a.send(Purpose::Control, b"overflow").err(),
        Some(Error::Full)
    );
    for frame in frames[1..].iter().rev() {
        a.flow.accept_credit(&b.receive(frame)).unwrap();
    }
    assert_eq!(a.flow.credited_floor(), 1);
    assert_eq!(b.flow.received_floor(), 1);
    assert_eq!(
        a.flow.retries().map(|(n, _, _)| n).collect::<Vec<_>>(),
        vec![2]
    );
    assert_eq!(a.flow.retries().next().unwrap().2, frames[0].encode());
    assert_eq!(
        a.send(Purpose::Control, b"still full").err(),
        Some(Error::Full)
    );
    a.reload();
    b.reload();
    a.flow.accept_credit(&b.receive(&frames[0])).unwrap();
    assert_eq!(a.flow.credited_floor(), 64);
    assert_eq!(b.ratchet.skipped_keys(), 0);
    assert_eq!(a.flow.cached_payload_bytes(), 0);
    assert_eq!(a.send(Purpose::Bulk, b"resumed").unwrap().ctr, 65);
}

#[test]
fn both_directions_can_release_full_windows_without_ratcheting_a_receipt() {
    let (mut a, mut b) = pair();
    let af: Vec<_> = (0..COUNTER_WINDOW)
        .map(|_| a.send(Purpose::Control, b"a").unwrap())
        .collect();
    let bf: Vec<_> = (0..COUNTER_WINDOW)
        .map(|_| b.send(Purpose::Control, b"b").unwrap())
        .collect();
    for f in &af {
        b.receive(f);
    }
    for f in &bf {
        a.receive(f);
    }
    assert_eq!(a.flow.next_counter(Purpose::Control), Err(Error::Full));
    assert_eq!(b.flow.next_counter(Purpose::Control), Err(Error::Full));
    let before = (a.ratchet.send_ctr(), b.ratchet.send_ctr());
    a.reload();
    b.reload();
    let ac = a
        .flow
        .credit_for_duplicate(bf[0].ctr, &bf[0].encode())
        .unwrap();
    let bc = b
        .flow
        .credit_for_duplicate(af[0].ctr, &af[0].encode())
        .unwrap();
    a.flow.accept_credit(&bc).unwrap();
    b.flow.accept_credit(&ac).unwrap();
    assert_eq!((a.ratchet.send_ctr(), b.ratchet.send_ctr()), before);
    assert_eq!(a.flow.cached_payload_bytes(), 0);
    assert_eq!(b.flow.cached_payload_bytes(), 0);
    assert!(a.flow.next_counter(Purpose::Bulk).is_ok());
    assert!(b.flow.next_counter(Purpose::Bulk).is_ok());
    // Receipt acceptance itself produces no traffic and no new retry.
    assert_eq!(a.flow.retries().count() + b.flow.retries().count(), 0);
}

#[test]
fn bulk_preserves_interactive_and_control_counter_reservations() {
    let (mut a, mut b) = pair();
    for _ in 0..BULK_WINDOW {
        a.send(Purpose::Bulk, b"file").unwrap();
    }
    assert_eq!(a.flow.next_counter(Purpose::Bulk), Err(Error::Full));
    for _ in BULK_WINDOW..INTERACTIVE_WINDOW {
        a.send(Purpose::Interactive, b"chat").unwrap();
    }
    assert_eq!(a.flow.next_counter(Purpose::Interactive), Err(Error::Full));
    for _ in INTERACTIVE_WINDOW..COUNTER_WINDOW {
        a.send(Purpose::Control, b"logical ack").unwrap();
    }
    assert_eq!(a.flow.next_counter(Purpose::Control), Err(Error::Full));
    let packet = a.flow.retries().next().unwrap().2.to_vec();
    let credit = b.receive(&Frame::decode(&packet).unwrap());
    a.flow.accept_credit(&credit).unwrap();
    assert!(a.flow.next_counter(Purpose::Control).is_ok());
    assert_eq!(a.flow.next_counter(Purpose::Bulk), Err(Error::Full));
}

#[test]
fn reordered_receipts_never_renege_on_selective_coverage() {
    let (mut a, mut b) = pair();
    let f2 = a.send(Purpose::Bulk, b"two").unwrap();
    let f3 = a.send(Purpose::Bulk, b"three").unwrap();
    let f4 = a.send(Purpose::Bulk, b"four").unwrap();
    let old = b.receive(&f3);
    let newer = b.receive(&f4);
    assert!(a.flow.accept_credit(&newer).unwrap());
    assert!(!a.flow.accept_credit(&old).unwrap());
    assert_eq!(
        a.flow.retries().map(|(n, _, _)| n).collect::<Vec<_>>(),
        vec![2]
    );
    assert!(a.flow.accept_credit(&b.receive(&f2)).unwrap());
    assert_eq!(a.flow.credited_floor(), 4);
    assert_eq!(a.flow.accept_credit(&old), Err(Error::UnknownReceipt));
}

#[test]
fn a_receipt_is_bound_to_session_packet_secret_and_snapshot() {
    let (mut a, mut b) = pair();
    let frame = a.send(Purpose::Interactive, b"secret").unwrap();
    let credit = b.receive(&frame);
    let before = a.flow.encode_private();
    for index in 0..CREDIT_BYTES {
        let mut tampered = credit;
        tampered[index] ^= 1;
        assert!(a.flow.accept_credit(&tampered).is_err(), "byte {index}");
        assert_eq!(a.flow.encode_private(), before);
    }
    let mut packet = frame.encode();
    packet[0] ^= 1;
    assert_eq!(
        b.flow.credit_for_duplicate(frame.ctr, &packet),
        Err(Error::Authentication)
    );
    assert_eq!(
        b.flow
            .credit_for_duplicate(frame.ctr, &frame.encode())
            .unwrap(),
        credit
    );
    b.reload();
    assert_eq!(
        b.flow
            .credit_for_duplicate(frame.ctr, &frame.encode())
            .unwrap(),
        credit
    );
    a.flow.accept_credit(&credit).unwrap();
}

#[test]
fn failed_staged_receive_has_no_effect_and_expiry_does_not_drop_a_counter() {
    let (mut a, mut b) = pair();
    let frame = a.send(Purpose::Bulk, b"expired work").unwrap();
    let before = b.flow.encode_private();
    let prepared = b
        .ratchet
        .prepare_receive(&frame, &[7; 32], &b.context)
        .unwrap();
    let record = Record::decode(prepared.plaintext()).unwrap();
    assert!(record.expired(1000));
    let mut candidate = b.flow.clone();
    candidate
        .record_authenticated(frame.ctr, &frame.encode(), &record)
        .unwrap();
    candidate
        .credit_for_duplicate(frame.ctr, &frame.encode())
        .unwrap();
    // Persistence failed: discard both candidates; no bytes were emitted.
    drop(candidate);
    drop(prepared);
    assert_eq!(b.flow.encode_private(), before);
    assert_eq!(b.ratchet.recv_ctr(), 1);
    assert_eq!(a.flow.oldest_uncredited_unix(), Some(100));
    assert_eq!(a.flow.retries().next().unwrap().2, frame.encode());
    a.flow.accept_credit(&b.receive(&frame)).unwrap();
    assert_eq!(b.flow.received_floor(), 2);
}

#[test]
fn coverage_cache_stays_bounded_across_many_epochs_and_restarts() {
    let (mut a, mut b) = pair();
    a.ratchet
        .set_pq_policy(7, std::time::Duration::from_secs(3600));
    b.ratchet
        .set_pq_policy(7, std::time::Duration::from_secs(3600));
    for index in 0..140 {
        let f = a.send(Purpose::Bulk, b"data").unwrap();
        a.flow.accept_credit(&b.receive(&f)).unwrap();
        let f = b.send(Purpose::Control, b"application receipt").unwrap();
        b.flow.accept_credit(&a.receive(&f)).unwrap();
        if index % 10 == 0 {
            a.reload();
            b.reload();
        }
        assert!(a.flow.rx.len() <= COUNTER_WINDOW as usize);
        assert!(b.flow.rx.len() <= COUNTER_WINDOW as usize);
    }
    assert_eq!(a.flow.credited_floor(), 141);
    assert_eq!(b.flow.credited_floor(), 140);
    assert_eq!(
        a.flow.cached_payload_bytes() + b.flow.cached_payload_bytes(),
        0
    );
}

#[test]
fn private_state_rejects_truncation_trailing_bytes_bad_coverage_and_cached_aead() {
    let (mut a, mut b) = pair();
    let frame = a.send(Purpose::Interactive, b"retained").unwrap();
    b.receive(&frame);
    for flow in [&a.flow, &b.flow] {
        let bytes = flow.encode_private();
        for length in 0..bytes.len() {
            assert!(
                Window::decode_private(&bytes[..length]).is_err(),
                "length {length}"
            );
        }
        let mut malformed = bytes.to_vec();
        malformed.push(0);
        assert!(Window::decode_private(&malformed).is_err());
        let mut malformed = bytes.to_vec();
        malformed[44] |= 1; // credited bitmap bit zero is noncanonical
        assert!(Window::decode_private(&malformed).is_err());
        assert_eq!(
            Window::decode_private(&bytes).unwrap().encode_private(),
            bytes
        );
    }
    let mut bytes = b.flow.encode_private().to_vec();
    *bytes.last_mut().unwrap() ^= 1;
    assert!(Window::decode_private(&bytes).is_err());
    assert!(Window::decode_private(&vec![0; storage::MAX_PRIVATE_BYTES + 1]).is_err());
}

#[test]
fn record_bounds_and_counter_overflow_fail_before_ratchet_preparation() {
    let mut rng = StdRng::seed_from_u64(9);
    assert!(Record::new(Purpose::Bulk, 0, b"invalid", &mut rng).is_err());
    assert!(Record::new(Purpose::Bulk, 10, &vec![0; MAX_RECORD_BODY + 1], &mut rng).is_err());
    let record = Record::new(Purpose::Bulk, 10, &vec![0; MAX_RECORD_BODY], &mut rng).unwrap();
    let bytes = record.encode();
    assert_eq!(
        Record::decode(&bytes).unwrap().body().len(),
        MAX_RECORD_BODY
    );
    assert!(Record::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut bad = bytes.to_vec();
    bad.push(0);
    assert!(Record::decode(&bad).is_err());
    let mut flow = Window::new([1; 16]).unwrap();
    flow.sent = u64::MAX;
    flow.credited.floor = u64::MAX;
    assert_eq!(flow.next_counter(Purpose::Control), Err(Error::Counter));
    assert!(Coverage {
        floor: u64::MAX,
        mask: 0
    }
    .contains(u64::MAX));
    assert!(!Coverage {
        floor: u64::MAX,
        mask: 2
    }
    .valid());
}

#[test]
fn prepared_session_transactions_reject_stale_and_cross_session_commits() {
    let (a, b) = pair();
    let context = a.context.clone();
    let mut one = CreditedSession::from_authenticated(a.ratchet.clone(), a.flow.clone()).unwrap();
    let mut other = CreditedSession::from_authenticated(a.ratchet, a.flow).unwrap();
    let mut receiver = CreditedSession::from_authenticated(b.ratchet, b.flow).unwrap();
    let record = Record::new(Purpose::Interactive, 1000, b"one", &mut rand::rngs::OsRng).unwrap();
    let first = one.prepare_send(&record, 100, &[7; 32], &context).unwrap();
    let stale = one.prepare_send(&record, 100, &[7; 32], &context).unwrap();
    let cross = one.prepare_send(&record, 100, &[7; 32], &context).unwrap();
    assert_eq!(
        Frame::decode(first.wire()).unwrap().ctr,
        Frame::decode(stale.wire()).unwrap().ctr,
        "both candidates compete for the same uncommitted counter"
    );
    assert_eq!(one.window().sent_counter(), 1);
    assert!(matches!(
        other.commit_send(cross),
        Err(SessionError::StaleTransaction)
    ));
    assert_eq!(other.window().sent_counter(), 1);
    let packet = first.wire().to_vec();
    let sealed = first.sealed_ratchet().clone();
    let private = first.private_flow();
    one.commit_send(first).unwrap();
    assert!(matches!(
        one.commit_send(stale),
        Err(SessionError::StaleTransaction)
    ));
    let received = receiver
        .prepare_receive(&Frame::decode(&packet).unwrap(), &[7; 32], &b.context)
        .unwrap();
    assert_eq!(received.record().unwrap().body(), b"one");
    let credit = *received.credit();
    receiver.commit_receive(received).unwrap();
    // Reopen the paired persisted snapshots, preserving the exact retry bytes.
    one = CreditedSession::restore(&sealed, &private, &[7; 32], &context).unwrap();
    assert_eq!(
        one.window().retries().next().unwrap().2,
        crate::gc2_session::encode_frame(one.window().session(), &Frame::decode(&packet).unwrap())
            .unwrap()
    );
    let send_before_credit = one.prepare_send(&record, 101, &[7; 32], &context).unwrap();
    let prepared_credit = one.prepare_credit(&credit).unwrap().unwrap();
    assert_eq!(prepared_credit.cached_payload_bytes(), 0);
    assert_ne!(one.window().cached_payload_bytes(), 0);
    one.commit_credit(prepared_credit).unwrap();
    assert!(matches!(
        one.commit_send(send_before_credit),
        Err(SessionError::StaleTransaction)
    ));
    assert_eq!(one.window().sent_counter(), 2);
    assert_eq!(one.window().cached_payload_bytes(), 0);
}

#[test]
fn duplicate_receive_after_restart_cannot_repeat_application_effects() {
    let (mut a, b) = pair();
    let frame = a.send(Purpose::Interactive, b"once").unwrap();
    let mut receiver = CreditedSession::from_authenticated(b.ratchet, b.flow).unwrap();
    let prepared = receiver
        .prepare_receive(&frame, &[7; 32], &b.context)
        .unwrap();
    let sealed = prepared.sealed_ratchet().unwrap().clone();
    let private = prepared.private_flow();
    let credit = *prepared.credit();
    assert!(prepared.record().is_some());
    receiver.commit_receive(prepared).unwrap();
    receiver = CreditedSession::restore(&sealed, &private, &[7; 32], &b.context).unwrap();
    let duplicate = receiver
        .prepare_receive(&frame, &[7; 32], &b.context)
        .unwrap();
    assert!(duplicate.record().is_none());
    assert!(duplicate.sealed_ratchet().is_none());
    assert_eq!(duplicate.credit(), &credit);
    receiver.commit_receive(duplicate).unwrap();
    let mut forged = frame.clone();
    forged.ct[0] ^= 1;
    assert!(receiver
        .prepare_receive(&forged, &[7; 32], &b.context)
        .is_err());
    assert_eq!(receiver.window().received_floor(), frame.ctr);
}

#[test]
fn overdue_counter_requires_explicit_recovery_and_mismatched_restore_fails() {
    let (mut a, _) = pair();
    a.send(Purpose::Bulk, b"lost").unwrap();
    let context = a.context.clone();
    let mut broken = a.flow.clone();
    broken.sent += 1;
    assert!(CreditedSession::from_authenticated(a.ratchet.clone(), broken).is_err());
    let session = CreditedSession::from_authenticated(a.ratchet, a.flow).unwrap();
    let ttl = gcoms_crypto::session::SKIP_KEY_TTL.as_secs();
    assert!(!session.window().repair_expired(100 + ttl - 1));
    assert!(session.window().repair_expired(100 + ttl));
    let record = Record::new(Purpose::Control, 0, b"later", &mut rand::rngs::OsRng).unwrap();
    assert!(matches!(
        session.prepare_send(&record, 100 + ttl, &[7; 32], &context),
        Err(SessionError::RecoveryRequired)
    ));
    assert_eq!(session.window().sent_counter(), 2);
    assert_eq!(session.window().retries().count(), 1);
}
