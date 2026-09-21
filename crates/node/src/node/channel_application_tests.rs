use super::*;
use bytes::Bytes;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

type ObservedPush = (Cell, h2::SendStream<Bytes>);

async fn terminal(
    mut contact: AliasContact,
) -> (
    AliasContact,
    mpsc::Receiver<ObservedPush>,
    tokio::task::JoinHandle<()>,
) {
    let identity = TlsIdentity::generate().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    contact.target = RelayTarget {
        address: listener.local_addr().unwrap(),
        relay_service_id: identity.service_id(),
    };
    contact.expiry = now_unix() + 3600;
    let expected = contact.clone();
    let acceptor = TlsAcceptor::from(Arc::new(identity.server_config().unwrap()));
    let (observed, received) = mpsc::channel(4);
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        let mut connection = h2::server::handshake(tls).await.unwrap();
        let mut requests = tokio::task::JoinSet::new();
        while let Some(Ok((request, mut reply))) = connection.accept().await {
            let expected = expected.clone();
            let observed = observed.clone();
            requests.spawn(async move {
                assert_eq!(
                    request.uri().path(),
                    format!("/{}", encode_b64url(&expected.queue_id))
                );
                let mut body = request.into_body();
                let mut wire = Vec::new();
                while let Some(Ok(bytes)) = body.data().await {
                    body.flow_control().release_capacity(bytes.len()).unwrap();
                    wire.extend_from_slice(&bytes);
                }
                let cell = gcoms_core::decode(&wire).unwrap();
                let push = crate::relay::RelayPush::decode_from_cell(
                    &cell,
                    &expected.push_cap,
                    &expected.target.relay_service_id,
                    now_unix(),
                )
                .unwrap();
                let mut send = reply.send_response(http::Response::new(()), false).unwrap();
                if let Some(message) = push.msg {
                    observed.send((message, send)).await.unwrap();
                } else {
                    send.send_data(
                        Bytes::from(
                            gcoms_transport::HopReply::Accepted
                                .cell()
                                .encode_wire()
                                .unwrap(),
                        ),
                        true,
                    )
                    .unwrap();
                }
            });
            while requests.try_join_next().is_some() {}
        }
        requests.shutdown().await;
    });
    (contact, received, task)
}

fn application() -> Vec<u8> {
    let content = gcoms_core::PIECE_CONTENT_TYPE.as_bytes();
    let mut body = b"GCAPP1".to_vec();
    body.extend_from_slice(&(content.len() as u16).to_be_bytes());
    body.extend_from_slice(content);
    body.extend_from_slice(b"bounded application fixture");
    body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_receipt_does_not_hold_channel_preparation_for_an_independent_peer() {
    let mut channel = persist::tests::established_owner_fixture("files");
    let mut peers = Vec::new();
    for index in 0..2u8 {
        let name = format!("peer{index}");
        let prepared = gcoms_mls::ChannelMember::prepare(&name).unwrap();
        let package = gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap();
        let crate::channel::ChannelRole::Owner(owner) = &mut channel.role else {
            unreachable!()
        };
        let invitation =
            owner.sign_invite_key_package(&package, &name, gcoms_mls::Caps::member(), 3600);
        let admitted = owner.admit(&invitation, &package).unwrap();
        let member = gcoms_mls::ChannelMember::join(prepared, &admitted.welcome).unwrap();
        let route = persist::tests::owned_channel_route(
            80 + index,
            member.own_pseudonym(),
            [90 + index; 32],
        );
        peers.push((name, route.public));
    }
    let (slow_contact, mut slow_rx, slow_server) = terminal(peers[0].1.control.clone()).await;
    let (fast_contact, mut fast_rx, fast_server) = terminal(peers[1].1.control.clone()).await;
    peers[0].1.control = slow_contact;
    peers[1].1.control = fast_contact;
    let recipients = [peers[0].1.pseudonym, peers[1].1.pseudonym];
    for (name, route) in peers {
        channel.directory.insert(name, route);
    }

    let scheduler = RelayScheduler::with_profile(
        Arc::new(Tp1Client::new().unwrap()),
        SchedulerProfile::compressed_production(38),
    );
    let mut node = persist::tests::state();
    node.scheduler.shutdown();
    node.scheduler = scheduler.clone();
    node.channels.insert("files".into(), channel);
    let state = Arc::new(Mutex::new(node));
    let (events_tx, _) = broadcast::channel(8);
    let (commands, cmd_rx) = mpsc::channel(8);
    let owner = spawn_command_loop(CommandLoopContext {
        state,
        frwd_admitted: Default::default(),
        scheduler: scheduler.clone(),
        events_tx,
        #[cfg(feature = "relay-host")]
        relay_host: None,
        cmd_rx,
    });

    let (slow_done, mut slow_result) = tokio::sync::oneshot::channel();
    commands
        .send(Cmd::SendChannelDirect {
            channel: "files".into(),
            recipient: recipients[0],
            text: application(),
            done: slow_done,
        })
        .await
        .unwrap();
    let (_, held_reply) = tokio::time::timeout(Duration::from_secs(5), slow_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let (fast_done, fast_result) = tokio::sync::oneshot::channel();
    commands
        .send(Cmd::SendChannelDirect {
            channel: "files".into(),
            recipient: recipients[1],
            text: application(),
            done: fast_done,
        })
        .await
        .unwrap();
    let (message, mut reply) = tokio::time::timeout(Duration::from_secs(3), fast_rx.recv())
        .await
        .expect("a pending file receipt must not hold the entire channel")
        .unwrap();
    assert_eq!(message.raw_type, CellType::Msg as u8);
    reply
        .send_data(
            Bytes::from(
                gcoms_transport::HopReply::Accepted
                    .cell()
                    .encode_wire()
                    .unwrap(),
            ),
            true,
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), fast_result)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(
        slow_result.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));

    let (done, stopped) = tokio::sync::oneshot::channel();
    commands.send(Cmd::Shutdown { done }).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), stopped)
        .await
        .unwrap()
        .unwrap();
    owner.await.unwrap();
    assert!(slow_result.await.unwrap().is_err());
    drop(held_reply);
    for task in [slow_server, fast_server] {
        task.abort();
        let _ = task.await;
    }
}
