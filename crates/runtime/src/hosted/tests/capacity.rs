//! Durable client/service capacity, separate from protected-network qualification.
use super::*;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

struct Measured {
    inner: Arc<TransportFixture>,
    covered_bytes: AtomicU64,
    bulk_bytes: AtomicU64,
}
#[async_trait]
impl Transport for Measured {
    async fn exchange(
        &self,
        channel: [u8; 32],
        operation: wire::Operation,
    ) -> Result<wire::Reply, String> {
        let bulk = operation.requires_bulk();
        if matches!(
            operation,
            wire::Operation::Acknowledge { .. }
                | wire::Operation::Receipts { .. }
                | wire::Operation::Poll { .. }
        ) {
            assert!(!bulk, "receipt traffic must remain covered");
        }
        let request_bytes = serde_json::to_vec(&wire::Request {
            version: wire::VERSION,
            channel,
            operation: operation.clone(),
        })
        .unwrap()
        .len();
        let reply = self.inner.exchange(channel, operation).await?;
        let bytes = request_bytes + serde_json::to_vec(&reply).unwrap().len();
        if bulk {
            &self.bulk_bytes
        } else {
            &self.covered_bytes
        }
        .fetch_add(bytes as u64, Ordering::Relaxed);
        Ok(reply)
    }
}
fn transport(path: &Path) -> Arc<Measured> {
    Arc::new(Measured {
        inner: Arc::new(TransportFixture {
            service: Service::open(Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                directory: path.into(),
                tls_terminated_upstream: false,
                creation: CreationPolicy::Public,
                max_channels: 1,
                max_total_bytes: 1024 * 1024 * 1024,
                channel_bytes: 1024 * 1024 * 1024,
                channel_records: 2000,
                requests_per_second: 100_000,
                source_requests_per_second: 100_000,
                blocked_channels: vec![],
                blocked_sources: vec![],
                motd: String::new(),
                rules: String::new(),
                operator_contact: String::new(),
            })
            .unwrap(),
            lose_acceptance: AtomicBool::new(false),
            lose_acknowledgment: AtomicBool::new(false),
        }),
        covered_bytes: AtomicU64::new(0),
        bulk_bytes: AtomicU64::new(0),
    })
}
fn consume(client: &mut Client) -> Vec<api::Event> {
    let mut all = Vec::new();
    loop {
        let events = client.events(0, 256).unwrap();
        let Some(last) = events.last() else {
            break;
        };
        client.commit_events(last.sequence).unwrap();
        all.extend(events);
    }
    all
}
async fn catch_up(client: &mut Client) {
    while client.sync_page().await.unwrap() {
        consume(client);
    }
    consume(client);
    while client.flush_one().await.unwrap() {}
}
fn restored(dir: &Path, channel: [u8; 32], transport: Arc<dyn Transport>) -> Client {
    let (storage, bytes) =
        storage::Storage::open(&dir.join(filename(channel)), [99; 32], channel).unwrap();
    Client::restore(&bytes.unwrap(), channel, storage, [99; 32], transport).unwrap()
}
fn has_delivery(events: &[api::Event], id: [u8; 32]) -> bool {
    events.iter().any(|e| matches!(e.kind, api::EventKind::Delivery { id: got, state: api::Delivery::Delivered } if got == id))
}
async fn run(members: usize) {
    assert!((12..=500).contains(&members));
    let started = Instant::now();
    let server = private_dir();
    let network = transport(server.path());
    let dirs: Vec<_> = (0..members + 1).map(|_| private_dir()).collect();
    let first = owner(dirs[0].path(), network.clone()).await;
    let channel = first.archive.channel;
    let mut clients = vec![first];
    let mut max_join_ms = 0;
    for (index, dir) in dirs.iter().enumerate().take(members).skip(1) {
        let joined = Instant::now();
        let mut client = joining(
            channel,
            &format!("member-{index}"),
            dir.path(),
            network.clone(),
        )
        .await;
        client.flush_one().await.unwrap();
        assert!(client.view().active);
        assert_eq!(client.view().members.len(), index + 1);
        max_join_ms = max_join_ms.max(joined.elapsed().as_millis());
        clients.push(client);
        if index % 25 == 0 {
            eprintln!(
                "hosted_runtime_capacity admitted={} seconds={:.3}",
                index + 1,
                started.elapsed().as_secs_f64()
            );
        }
    }
    let admission_seconds = started.elapsed().as_secs_f64();
    // The owner was absent during every external admission. Every retained
    // client now replays ordered commits through its own encrypted sidecar.
    eprintln!("hosted_runtime_capacity stage=admission_complete members={members} seconds={admission_seconds:.3}");
    let mut replay_checkpoints = 0;
    for (index, client) in clients.iter_mut().enumerate() {
        let before = client.checkpoint_count();
        catch_up(client).await;
        replay_checkpoints += client.checkpoint_count() - before;
        assert_eq!(client.view().members.len(), members);
        if index % 25 == 0 {
            eprintln!(
                "hosted_runtime_capacity stage=catch_up clients={} checkpoints={replay_checkpoints} seconds={:.3}",
                index + 1,
                started.elapsed().as_secs_f64()
            );
        }
    }
    // A single topic handoff can be queued by the owner during convergence.
    for client in &mut clients {
        catch_up(client).await;
    }
    let mut offline = clients.pop().unwrap();
    let offline_member = offline.session.member_id();
    consume(&mut offline);
    drop(offline);
    eprintln!(
        "hosted_runtime_capacity stage=send seconds={:.3}",
        started.elapsed().as_secs_f64()
    );
    let mut sends = tokio::task::JoinSet::new();
    // Ten independent actual client owners persist and publish concurrently.
    for (index, mut client) in clients.drain(..10).enumerate() {
        sends.spawn(async move {
            let queued = Instant::now();
            let id = client
                .queue_send(api::Content::Text(format!("capacity-message-{index}")))
                .unwrap();
            let local_ms = queued.elapsed().as_millis();
            while client.flush_one().await.unwrap() {}
            (index, client, id, local_ms)
        });
    }
    let mut senders = Vec::new();
    while let Some(result) = sends.join_next().await {
        senders.push(result.unwrap());
    }
    senders.sort_by_key(|(index, ..)| *index);
    let ids: Vec<_> = senders.iter().map(|(_, _, id, _)| *id).collect();
    let max_feedback_ms = senders.iter().map(|(_, _, _, ms)| *ms).max().unwrap();
    let mut ordered: Vec<_> = senders
        .into_iter()
        .map(|(_, client, _, _)| client)
        .collect();
    ordered.append(&mut clients);
    clients = ordered;
    let mut receives = 0;
    for client in &mut clients {
        while client.sync_page().await.unwrap() {}
        let events = consume(client);
        receives += events.iter().filter(|e| matches!(&e.kind, api::EventKind::Message { content: api::Content::Text(text), .. } if text.starts_with("capacity-message-"))).count();
        for id in &ids {
            assert!(
                !has_delivery(&events, *id),
                "offline recipient cannot be marked delivered"
            );
        }
        client.sync_page().await.unwrap();
    }
    // Fetch enough covered receipt pages to prove that the missing peer, not
    // an unread page, is what prevents Delivered.
    for (index, client) in clients.iter_mut().take(10).enumerate() {
        for _ in 0..members.div_ceil(32) + 2 {
            client.sync_page().await.unwrap();
        }
        assert!(!has_delivery(&consume(client), ids[index]));
    }
    eprintln!(
        "hosted_runtime_capacity stage=offline_recovery seconds={:.3}",
        started.elapsed().as_secs_f64()
    );
    let recovered = Instant::now();
    let mut offline = restored(dirs[members - 1].path(), channel, network.clone());
    while offline.sync_page().await.unwrap() {}
    let events = consume(&mut offline);
    assert_eq!(events.iter().filter(|e| matches!(&e.kind, api::EventKind::Message { content: api::Content::Text(text), .. } if text.starts_with("capacity-message-"))).count(), 10);
    offline.sync_page().await.unwrap();
    let recovery_ms = recovered.elapsed().as_millis();
    clients.push(offline);
    for (index, client) in clients.iter_mut().take(10).enumerate() {
        let mut events = Vec::new();
        for _ in 0..members.div_ceil(32) + 2 {
            client.sync_page().await.unwrap();
            events.extend(consume(client));
        }
        assert!(
            has_delivery(&events, ids[index]),
            "every original recipient must authenticate delivery"
        );
    }
    assert_eq!(
        receives + 10,
        members * 10,
        "each client retains ten messages including its own"
    );
    // Store real AEAD ciphertext; only clients hold the encryption key. This
    // checks the piece carrier at capacity, not the separate whole-file engine.
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    let cipher = Aes256Gcm::new_from_slice(&[61; 32]).unwrap();
    let plaintext = vec![27; 256 * 1024];
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&[17; 12]), plaintext.as_slice())
        .unwrap();
    let reference = wire::BlobRef {
        owner: clients[0].session.member_id(),
        file: [81; 16],
        piece: 0,
    };
    clients[0]
        .blob(reference, Some(ciphertext.clone()))
        .await
        .unwrap();
    let api::Reply::Blob(bytes) = clients[members - 1].blob(reference, None).await.unwrap() else {
        panic!("ciphertext piece");
    };
    assert_eq!(bytes, ciphertext);
    assert_eq!(
        cipher
            .decrypt(Nonce::from_slice(&[17; 12]), bytes.as_slice())
            .unwrap(),
        plaintext
    );
    eprintln!(
        "hosted_runtime_capacity stage=churn seconds={:.3}",
        started.elapsed().as_secs_f64()
    );
    clients[0]
        .queue_control(HostedPolicyChange::Kick(offline_member), "capacity churn")
        .unwrap();
    while clients[0].flush_one().await.unwrap() {}
    catch_up(&mut clients[0]).await;
    catch_up(&mut clients[0]).await;
    for client in &mut clients[1..members - 1] {
        catch_up(client).await;
    }
    assert!(
        clients[members - 1].blob(reference, None).await.is_err(),
        "removed peer cannot fetch ciphertext"
    );
    let mut replacement = joining(
        channel,
        "replacement",
        dirs[members].path(),
        network.clone(),
    )
    .await;
    replacement.flush_one().await.unwrap();
    assert_eq!(replacement.view().members.len(), members);
    for client in &mut clients[..members - 1] {
        catch_up(client).await;
        assert_eq!(client.view().members.len(), members);
    }
    eprintln!("hosted_runtime_capacity_result members={members} senders=10 messages={} admission_seconds={admission_seconds:.3} max_join_ms={max_join_ms} max_feedback_ms={max_feedback_ms} recovery_ms={recovery_ms} covered_json_bytes={} bulk_json_bytes={} total_seconds={:.3} transport=in_process", members*10, network.covered_bytes.load(Ordering::Relaxed), network.bulk_bytes.load(Ordering::Relaxed), started.elapsed().as_secs_f64());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_hosted_capacity_smoke() {
    run(12).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit 500-client durable capacity campaign; in-process transport, not a protected-network latency gate"]
async fn five_hundred_durable_hosted_clients_ten_senders_offline_and_churn() {
    run(500).await;
}
