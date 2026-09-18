fn gc2_node(seed: u8) -> NodeState {
    let mut node = state();
    let identity = IdentityKeypair::from_seed([seed;32]);
    let (bundle,secrets) = identity.issue_bundle();
    node.identity_seed=[seed;32];
    node.info.identity_pk=identity.public_bytes();
    node.info.bundle=bundle.encode();
    node.secrets=Arc::new(secrets);
    node.gc2_sessions=true;
    node.durable_applications_enabled=true;
    node.durable_state_sink=Some(Arc::new(|_|Ok(())));
    node
}

async fn gc2_restore(node: &NodeState, seed: u8) -> Arc<Mutex<NodeState>> {
    let bytes=encode_state(node).unwrap();
    assert_eq!(&bytes[..6],MAGIC_V21);
    let mut fresh=gc2_node(seed);
    // A node restart reopens the existing identity bundle and private keys.
    fresh.info=node.info.clone();
    fresh.secrets=node.secrets.clone();
    fresh.scheduler.shutdown();
    fresh.scheduler=node.scheduler.clone();
    let fresh=Arc::new(Mutex::new(fresh));
    decode_state_at_startup(&fresh,&node.scheduler,&bytes).await.unwrap();
    fresh
}

#[tokio::test]
async fn gc2_durable_file_records_reserve_the_bulk_counter_window() {
    fn file_record(body: &[u8]) -> Vec<u8> {
        let mut application = b"GCAPP1".to_vec();
        application
            .extend_from_slice(&(gcoms_core::FILE_RECORD_CONTENT_TYPE.len() as u16).to_be_bytes());
        application.extend_from_slice(gcoms_core::FILE_RECORD_CONTENT_TYPE.as_bytes());
        application.extend_from_slice(body);
        gcoms_core::component::RoutedApplication {
            source: [11; 16],
            destination: [12; 16],
            application,
        }
        .encode()
        .unwrap()
    }
    let alice = Arc::new(Mutex::new(gc2_node(87)));
    let bob = gc2_node(88);
    let scheduler = alice.lock().unwrap().scheduler.clone();
    send_durable_1to1(
        &alice,
        &scheduler,
        &bob.info,
        &file_record(b"file chunk"),
        None,
    )
    .await
    .unwrap();
    let peer = bob.info.identity_pk.clone();
    alice
        .lock()
        .unwrap()
        .session_states
        .insert(peer.clone(), DirectSessionState::Established);
    send_durable_1to1(&alice, &scheduler, &bob.info, b"chat", None)
        .await
        .unwrap();
    let a = alice.lock().unwrap();
    let PeerSession::Credited(session) = &a.sessions[&peer] else {
        panic!("GC2 session expected");
    };
    let purposes: Vec<_> = session
        .window()
        .retries()
        .map(|(_, purpose, _)| purpose)
        .collect();
    assert!(purposes.contains(&gcoms_protocol::flow::Purpose::Bulk));
    assert!(purposes.contains(&gcoms_protocol::flow::Purpose::Interactive));
    a.scheduler.shutdown();
    bob.scheduler.shutdown();
}

#[tokio::test]
async fn gc2_runtime_durable_delivery_credit_and_ack_survive_restart() {
    let alice=Arc::new(Mutex::new(gc2_node(21)));
    let mut bob=gc2_node(22);
    let scheduler=alice.lock().unwrap().scheduler.clone();
    send_durable_1to1(&alice,&scheduler,&bob.info,b"GC2 durable body",None).await.unwrap();
    let (id,cells,ai)={ let a=alice.lock().unwrap(); let (id,p)=a.pending_1to1.iter().next().unwrap(); (*id,p.delivery.cells.clone(),a.info.clone()) };
    assert_eq!(cells.len(),2);
    assert!(cells.iter().all(|c|c.flags==0));
    let (events,mut rx)=broadcast::channel(32);
    gc2_direct::incoming(&mut bob,&cells[0].payload,&events).unwrap();
    let lost_credit=bob.direct_ack_outbox.pop_front().unwrap();
    let restored=gc2_restore(&bob,22).await;
    let mut bob=restored.lock().unwrap();
    gc2_direct::incoming(&mut bob,&cells[0].payload,&events).unwrap();
    assert_eq!(bob.direct_ack_outbox.back().unwrap().cells,lost_credit.cells);
    gc2_direct::incoming(&mut bob,&cells[1].payload,&events).unwrap();
    assert_eq!(bob.application_inbox.entries.len(),1);
    assert_eq!(bob.application_inbox.entries[0].body,b"GC2 durable body");
    let archived=encode_state(&bob).unwrap();
    let snapshot=decode_v2(&archived,&[22;32]).unwrap();
    assert_eq!(snapshot.application_inbox.entries.len(),1);
    let count=bob.sessions[&ai.identity_pk].send_ctr();
    gc2_direct::incoming(&mut bob,&cells[1].payload,&events).unwrap();
    assert_eq!(bob.application_inbox.entries.len(),1);
    assert_eq!(bob.sessions[&ai.identity_pk].send_ctr(),count);
    // Credits can clear transport state while the application ACK is still lost.
    let outbox:Vec<_>=bob.direct_ack_outbox.iter().flat_map(|d|d.cells.clone()).collect();
    let mut a=alice.lock().unwrap();
    for cell in outbox.iter().filter(|c|c.payload.starts_with(b"GCA2")) {
        let _=gc2_direct::incoming(&mut a,&cell.payload,&events);
    }
    assert!(a.pending_1to1.contains_key(&id));
    for cell in outbox.iter().filter(|c|c.payload.starts_with(b"GCM2")) {
        gc2_direct::incoming(&mut a,&cell.payload,&events).unwrap();
    }
    assert!(!a.pending_1to1.contains_key(&id));
    let PeerSession::Credited(s)=&a.sessions[&bob.info.identity_pk] else {panic!("GC2 session")};
    assert_eq!(s.window().cached_payload_bytes(),0);
    let delivered=std::iter::from_fn(||rx.try_recv().ok()).filter(|e|matches!(e,Ev::DirectDelivery {msg_id,..} if *msg_id==id)).count();
    assert_eq!(delivered,1);
    scheduler.shutdown(); bob.scheduler.shutdown();
}

#[tokio::test]
async fn gc2_runtime_failed_receive_write_has_no_application_effect_or_credit() {
    let alice=Arc::new(Mutex::new(gc2_node(23)));
    let mut bob=gc2_node(24);
    let scheduler=alice.lock().unwrap().scheduler.clone();
    send_durable_1to1(&alice,&scheduler,&bob.info,b"do not publish early",None).await.unwrap();
    let cells=alice.lock().unwrap().pending_1to1.values().next().unwrap().delivery.cells.clone();
    let (events,_)=broadcast::channel(32);
    gc2_direct::incoming(&mut bob,&cells[0].payload,&events).unwrap();
    let before=bob.direct_ack_outbox.len();
    let ai=alice.lock().unwrap().info.identity_pk.clone();
    let received=bob.sessions[&ai].recv_ctr();
    let charged=bob.scheduler.resource_snapshot();
    bob.durable_state_sink=Some(Arc::new(|_|Err("receive failpoint".into())));
    gc2_direct::incoming(&mut bob,&cells[1].payload,&events).unwrap();
    assert_eq!(bob.direct_ack_outbox.len(),before);
    assert!(bob.application_inbox.entries.is_empty());
    assert_eq!(bob.sessions[&ai].recv_ctr(),received);
    assert_eq!(bob.scheduler.resource_snapshot().bytes,charged.bytes);
    assert_eq!(bob.scheduler.resource_snapshot().jobs,charged.jobs);
    bob.durable_state_sink=Some(Arc::new(|_|Ok(())));
    gc2_direct::incoming(&mut bob,&cells[1].payload,&events).unwrap();
    assert_eq!(bob.application_inbox.entries.len(),1);
    assert_eq!(bob.sessions[&ai].recv_ctr(),received+1);
    scheduler.shutdown(); bob.scheduler.shutdown();
}

#[tokio::test]
async fn gc2_runtime_retained_limit_applies_without_a_durable_sink() {
    let mut node=gc2_node(41);
    node.durable_state_sink=None;
    let scheduler=node.scheduler.clone();
    let alice=Arc::new(Mutex::new(node));
    let (events,_)=broadcast::channel(32);
    let body=vec![0x71;11*1024];
    let mut blocked=false;
    for seed in 42..46 {
        let mut bob=gc2_node(seed);
        send_direct_record(&alice,&scheduler,&bob.info,None,true,|id,_| Ok(crate::proto::encode_direct_durable_data(id,now_ms(),&body))).await.unwrap();
        let first=alice.lock().unwrap().pending_1to1.values()
            .find(|p|p.delivery.peer.identity_pk==bob.info.identity_pk).unwrap().delivery.cells[0].payload.clone();
        gc2_direct::incoming(&mut bob,&first,&events).unwrap();
        gc2_direct::incoming(&mut alice.lock().unwrap(),&bob.direct_ack_outbox[0].cells[0].payload,&events).unwrap();
        for _ in 1..32 {
            let (pending,sequence,counter)={let a=alice.lock().unwrap();(a.pending_1to1.len(),a.next_direct_sequence,a.sessions[&bob.info.identity_pk].send_ctr())};
            match send_direct_record(&alice,&scheduler,&bob.info,None,true,|id,_| Ok(crate::proto::encode_direct_durable_data(id,now_ms(),&body))).await {
                Ok(_) => (),
                Err(error) => {
                    assert!(error.contains("direct retained payload admission"),"{error}");
                    let a=alice.lock().unwrap();
                    assert_eq!(a.pending_1to1.len(),pending);
                    assert_eq!(a.next_direct_sequence,sequence);
                    assert_eq!(a.sessions[&bob.info.identity_pk].send_ctr(),counter);
                    assert!(!a.owner_transition_failed);
                    blocked=true;
                    break;
                }
            }
        }
        bob.scheduler.shutdown();
        if blocked {break;}
    }
    assert!(blocked,"stalled peers must share one retained-data limit");
    let a=alice.lock().unwrap();
    let retained=a.retained_payload(None).unwrap();
    assert!(retained.bytes > 2*1024*1024 && retained.bytes <= 3*1024*1024);
    assert!(scheduler.resource_snapshot().bytes >= retained.bytes);
    assert!(scheduler.combined_resource_snapshot().bytes <= crate::scheduler::MAX_QUEUED_BYTES);
    drop(a);
    drop(alice);
    scheduler.shutdown();
}

#[tokio::test]
async fn gc2_runtime_restore_reserves_before_publishing_and_reclaims_on_drop() {
    let alice=Arc::new(Mutex::new(gc2_node(47)));
    let bob=gc2_node(48);
    let scheduler=alice.lock().unwrap().scheduler.clone();
    send_durable_1to1(&alice,&scheduler,&bob.info,&vec![7;11*1024],None).await.unwrap();
    let (bytes,expected)={let a=alice.lock().unwrap();(encode_state(&a).unwrap(),a.retained_payload(None).unwrap())};
    let fresh=Arc::new(Mutex::new(gc2_node(47)));
    let fresh_scheduler=fresh.lock().unwrap().scheduler.clone();
    // A queued/live request competes atomically with a cold-restored outbox.
    let pressure=fresh_scheduler.retain_attempt_payload(7*1024*1024).unwrap();
    assert!(decode_state_at_startup(&fresh,&fresh_scheduler,&bytes).await.unwrap_err().contains("direct retained payload admission"));
    assert!(fresh.lock().unwrap().sessions.is_empty());
    assert!(fresh.lock().unwrap().pending_1to1.is_empty());
    drop(pressure);
    decode_state_at_startup(&fresh,&fresh_scheduler,&bytes).await.unwrap();
    assert_eq!(fresh_scheduler.resource_snapshot().bytes,expected.bytes);
    assert_eq!(fresh_scheduler.resource_snapshot().jobs,expected.items);
    assert!(decode_state_at_startup(&fresh,&fresh_scheduler,&bytes).await.unwrap_err().contains("live GC/2"));
    drop(fresh);
    assert_eq!(fresh_scheduler.resource_snapshot().bytes,0);
    assert_eq!(fresh_scheduler.resource_snapshot().jobs,0);
    scheduler.shutdown();bob.scheduler.shutdown();fresh_scheduler.shutdown();
}

#[tokio::test]
async fn gc2_runtime_deferred_materialization_waits_for_budget_without_pausing_node() {
    let alice=Arc::new(Mutex::new(gc2_node(49)));
    let mut bob=gc2_node(50);
    let scheduler=alice.lock().unwrap().scheduler.clone();
    send_durable_1to1(&alice,&scheduler,&bob.info,b"first",None).await.unwrap();
    send_durable_1to1(&alice,&scheduler,&bob.info,&vec![3;11*1024],None).await.unwrap();
    let deferred=*alice.lock().unwrap().pending_1to1.iter().find(|(_,p)|p.delivery.cells.is_empty()).unwrap().0;
    let (events,_)=broadcast::channel(32);
    let first=alice.lock().unwrap().pending_1to1.values().find(|p|!p.delivery.cells.is_empty()).unwrap().delivery.cells[0].payload.clone();
    gc2_direct::incoming(&mut bob,&first,&events).unwrap();
    let mut a=alice.lock().unwrap();
    gc2_direct::incoming(&mut a,&bob.direct_ack_outbox[0].cells[0].payload,&events).unwrap();
    let expires=a.pending_1to1[&deferred].expires;
    let sequence=a.pending_1to1[&deferred].sequence;
    let counter=a.sessions[&bob.info.identity_pk].send_ctr();
    let pressure=scheduler.retain_attempt_payload(7*1024*1024-scheduler.resource_snapshot().bytes).unwrap();
    materialize_deferred(&mut a).unwrap();
    assert!(!a.owner_transition_failed);
    assert!(a.pending_1to1[&deferred].delivery.cells.is_empty());
    assert_eq!(a.pending_1to1[&deferred].expires,expires);
    assert_eq!(a.pending_1to1[&deferred].sequence,sequence);
    assert_eq!(a.sessions[&bob.info.identity_pk].send_ctr(),counter);
    drop(pressure);
    materialize_deferred(&mut a).unwrap();
    assert_eq!(a.pending_1to1[&deferred].delivery.cells.len(),1);
    assert_eq!(a.sessions[&bob.info.identity_pk].send_ctr(),counter+1);
    assert_eq!(a.pending_1to1[&deferred].expires,expires);
    scheduler.shutdown();bob.scheduler.shutdown();
}

#[tokio::test]
async fn gc2_runtime_lost_application_ack_repairs_from_window_after_restart() {
    let alice=Arc::new(Mutex::new(gc2_node(51)));
    let mut bob=gc2_node(52);
    let scheduler=alice.lock().unwrap().scheduler.clone();
    send_durable_1to1(&alice,&scheduler,&bob.info,b"repair one application ACK",None).await.unwrap();
    let id=*alice.lock().unwrap().pending_1to1.keys().next().unwrap();
    let cells=alice.lock().unwrap().pending_1to1[&id].delivery.cells.clone();
    let (events,_)=broadcast::channel(32);
    for cell in &cells { gc2_direct::incoming(&mut bob,&cell.payload,&events).unwrap(); }
    assert!(bob.processed_direct.is_empty());
    let ack=bob.direct_ack_outbox.iter().flat_map(|d|&d.cells).find(|c|c.payload.starts_with(b"GCM2")).unwrap().payload.clone();
    // The relay accepted these packets, but the peer never received the ACK.
    bob.direct_ack_outbox.clear();
    bob.release_removed_direct_payload();
    let restored=gc2_restore(&bob,52).await;
    let mut b=restored.lock().unwrap();
    let mut a=alice.lock().unwrap();
    let PeerSession::Credited(session)=&b.sessions[&a.info.identity_pk] else {panic!("GC2")};
    assert!(session.window().retries().any(|(_,_,packet)|packet==ack));
    gc2_direct::incoming(&mut a,&ack,&events).unwrap();
    assert!(!a.pending_1to1.contains_key(&id));
    let credits:Vec<_>=a.direct_ack_outbox.iter().flat_map(|d|d.cells.clone()).collect();
    for credit in credits {gc2_direct::incoming(&mut b,&credit.payload,&events).unwrap();}
    let PeerSession::Credited(session)=&b.sessions[&a.info.identity_pk] else {panic!("GC2")};
    assert_eq!(session.window().cached_payload_bytes(),0);
    let counter=b.sessions[&a.info.identity_pk].send_ctr();
    gc2_direct::incoming(&mut b,&cells[1].payload,&events).unwrap();
    assert_eq!(b.application_inbox.entries.len(),1);
    assert_eq!(b.sessions[&a.info.identity_pk].send_ctr(),counter);
    assert!(b.direct_ack_outbox.iter().flat_map(|d|&d.cells).all(|c|c.payload.starts_with(b"GCA2")));
    scheduler.shutdown();b.scheduler.shutdown();
}

#[tokio::test]
async fn gc2_runtime_archive_requires_explicit_version_and_authenticates_credit_state() {
    let empty=gc2_node(25);
    let empty_archive=encode_state(&empty).unwrap();
    assert_eq!(&empty_archive[..6],MAGIC_V21);
    let legacy=Arc::new(Mutex::new(state()));
    assert!(decode_state_at_startup(&legacy,&empty.scheduler,&empty_archive).await.unwrap_err().contains("explicit GC/2"));
    legacy.lock().unwrap().scheduler.shutdown();
    empty.scheduler.shutdown();
    let alice=Arc::new(Mutex::new(gc2_node(25)));
    let bob=gc2_node(26);
    let scheduler=alice.lock().unwrap().scheduler.clone();
    send_durable_1to1(&alice,&scheduler,&bob.info,b"retained",None).await.unwrap();
    let archive=encode_state(&alice.lock().unwrap()).unwrap();
    let mut legacy_tag=archive.clone();legacy_tag[..6].copy_from_slice(MAGIC_V19);
    assert!(decode_v2(&legacy_tag,&[25;32]).is_err());
    let mut legacy=gc2_node(25);legacy.gc2_sessions=false;
    let legacy=Arc::new(Mutex::new(legacy));
    assert!(decode_state_at_startup(&legacy,&scheduler,&archive).await.unwrap_err().contains("explicit GC/2"));
    assert!(legacy.lock().unwrap().sessions.is_empty());
    let mut tampered=archive.clone();
    let start=tampered.windows(5).position(|w|w==b"GCPS\x02").unwrap();
    tampered[start+33]^=1;
    let fresh=Arc::new(Mutex::new(gc2_node(25)));
    assert!(decode_state_at_startup(&fresh,&scheduler,&tampered).await.is_err());
    assert!(fresh.lock().unwrap().sessions.is_empty());
    scheduler.shutdown();bob.scheduler.shutdown();legacy.lock().unwrap().scheduler.shutdown();fresh.lock().unwrap().scheduler.shutdown();
}

#[tokio::test]
async fn gc2_runtime_simultaneous_setup_preserves_ids_deadlines_and_session_version() {
    let a=Arc::new(Mutex::new(gc2_node(27)));
    let b=Arc::new(Mutex::new(gc2_node(28)));
    let ai=a.lock().unwrap().info.clone();let bi=b.lock().unwrap().info.clone();
    let sa=a.lock().unwrap().scheduler.clone();let sb=b.lock().unwrap().scheduler.clone();
    send_durable_1to1(&a,&sa,&bi,b"a",None).await.unwrap();
    send_durable_1to1(&b,&sb,&ai,b"b",None).await.unwrap();
    let first_a=a.lock().unwrap().pending_1to1.values().next().unwrap().delivery.cells[0].payload.clone();
    let first_b=b.lock().unwrap().pending_1to1.values().next().unwrap().delivery.cells[0].payload.clone();
    let (winner,loser,incoming_winner,incoming_loser)=if ai.identity_pk<bi.identity_pk {(&a,&b,first_a,first_b)} else {(&b,&a,first_b,first_a)};
    let (events,_)=broadcast::channel(32);
    assert!(gc2_direct::incoming(&mut winner.lock().unwrap(),&incoming_loser,&events).is_err());
    let mut loser=loser.lock().unwrap();
    let (id,expires,sequence)={let (id,p)=loser.pending_1to1.iter().next().unwrap();(*id,p.expires,p.sequence)};
    gc2_direct::incoming(&mut loser,&incoming_winner,&events).unwrap();
    assert!(loser.pending_1to1[&id].delivery.cells.is_empty());
    materialize_deferred(&mut loser).unwrap();
    assert_eq!(loser.pending_1to1[&id].expires,expires);
    assert_eq!(loser.pending_1to1[&id].sequence,sequence);
    assert_eq!(loser.pending_1to1[&id].delivery.cells.len(),1);
    assert!(loser.pending_1to1[&id].delivery.cells[0].payload.starts_with(b"GCM2"));
    assert!(decode_v2(&encode_state(&loser).unwrap(),&loser.identity_seed).is_ok());
    sa.shutdown();sb.shutdown();
}
