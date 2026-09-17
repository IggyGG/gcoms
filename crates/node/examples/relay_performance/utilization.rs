//! Experimental echo packing, confined to this loopback example. Not an app codec.
use super::*;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;

const PAYLOAD_LIMIT: usize = 12_000;
const FRAME_HEADER: usize = 8;
const QUEUE_LIMIT: usize = 8 * 1024 * 1024;
const JOB_LIMIT: usize = 4096;
const TRIAL_TIMEOUT_SECONDS: u64 = 120;
const CREDENTIAL_EPOCH_SECONDS: u64 = 3600;
const SCENARIOS: [&str; 6] = [
    "idle",
    "sparse_chat",
    "burst_chat",
    "bulk",
    "chat_bulk",
    "four_producers",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Chat,
    Bulk,
}

#[derive(Clone, Debug, Serialize)]
struct Message {
    id: u32,
    producer: usize,
    kind: Kind,
    at_us: u64,
    bytes: usize,
}

#[derive(Clone, Copy, Serialize)]
struct Variant {
    name: &'static str,
    window: usize,
    packing: bool,
}

const VARIANTS: [Variant; 4] = [
    Variant {
        name: "baseline",
        window: 1,
        packing: false,
    },
    Variant {
        name: "concurrency",
        window: 4,
        packing: false,
    },
    Variant {
        name: "packing",
        window: 1,
        packing: true,
    },
    Variant {
        name: "combined",
        window: 4,
        packing: true,
    },
];

fn credential_wait_seconds(now: u64) -> u64 {
    let remaining = CREDENTIAL_EPOCH_SECONDS - now % CREDENTIAL_EPOCH_SECONDS;
    if remaining <= TRIAL_TIMEOUT_SECONDS {
        remaining + 1
    } else {
        0
    }
}

async fn await_credential_window() -> (u64, u64, bool) {
    let waiting = Instant::now();
    let mut deferred = false;
    loop {
        let now = now_unix();
        let seconds = credential_wait_seconds(now);
        if seconds == 0 {
            return (now, waiting.elapsed().as_micros() as u64, deferred);
        }
        // No fixture, connection or offered message exists during this lab-only
        // pause. All arms require a credential lifetime longer than their deadline.
        deferred = true;
        eprintln!("utilization preflight: waiting {seconds}s for the next credential epoch");
        tokio::time::sleep(Duration::from_secs(seconds)).await;
    }
}

fn workload(name: &str, quick: bool) -> Vec<Message> {
    let mut messages = Vec::new();
    let producers = if name == "four_producers" { 4 } else { 1 };
    for producer in 0..producers {
        let chat = match name {
            "sparse_chat" | "chat_bulk" => 20,
            "burst_chat" => 32,
            "four_producers" => 8,
            _ => 0,
        };
        for index in 0..if quick { chat.min(2) } else { chat } {
            let at_us = if name == "burst_chat" {
                (index / 8) * 1_000_000
            } else if name == "sparse_chat" {
                index * 1_000_000
            } else {
                index * 250_000
            };
            messages.push(Message {
                id: messages.len() as u32,
                producer,
                kind: Kind::Chat,
                at_us,
                bytes: 128,
            });
        }
        let bulk = match name {
            "bulk" | "chat_bulk" => 16,
            "four_producers" => 4,
            _ => 0,
        };
        for _ in 0..if quick { bulk.min(2) } else { bulk } {
            messages.push(Message {
                id: messages.len() as u32,
                producer,
                kind: Kind::Bulk,
                at_us: 0,
                bytes: PAYLOAD_LIMIT - FRAME_HEADER,
            });
        }
    }
    messages.sort_by_key(|message| (message.at_us, message.id));
    messages
}

struct FairQueue {
    lanes: Vec<[VecDeque<Message>; 2]>,
    next_producer: usize,
    next_kind: Vec<usize>,
    bytes: usize,
    jobs: usize,
}

impl FairQueue {
    fn new(producers: usize) -> Self {
        Self {
            lanes: vec![[VecDeque::new(), VecDeque::new()]; producers],
            next_producer: 0,
            next_kind: vec![0; producers],
            bytes: 0,
            jobs: 0,
        }
    }

    fn push(&mut self, message: Message) -> bool {
        if self.bytes + message.bytes > QUEUE_LIMIT || self.jobs == JOB_LIMIT {
            return false;
        }
        self.bytes += message.bytes;
        self.jobs += 1;
        self.lanes[message.producer][usize::from(message.kind == Kind::Bulk)].push_back(message);
        true
    }

    fn pop(&mut self, packing: bool) -> Option<Vec<Message>> {
        for step in 0..self.lanes.len() {
            let producer = (self.next_producer + step) % self.lanes.len();
            for offset in 0..2 {
                let kind = (self.next_kind[producer] + offset) % 2;
                let lane = &mut self.lanes[producer][kind];
                let Some(first) = lane.pop_front() else {
                    continue;
                };
                let mut size = first.bytes + FRAME_HEADER;
                let mut batch = vec![first];
                // No timer: only this producer's already queued chat can be packed.
                while packing
                    && kind == 0
                    && lane
                        .front()
                        .is_some_and(|next| size + next.bytes + FRAME_HEADER <= PAYLOAD_LIMIT)
                {
                    let next = lane.pop_front().unwrap();
                    size += next.bytes + FRAME_HEADER;
                    batch.push(next);
                }
                self.bytes -= batch.iter().map(|message| message.bytes).sum::<usize>();
                self.jobs -= batch.len();
                self.next_producer = (producer + 1) % self.lanes.len();
                self.next_kind[producer] = 1 - kind;
                return Some(batch);
            }
        }
        None
    }
}

fn encode(batch: &[Message]) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    for message in batch {
        payload.extend_from_slice(&message.id.to_be_bytes());
        payload.extend_from_slice(&(message.bytes as u32).to_be_bytes());
        payload.resize(payload.len() + message.bytes, (message.id % 251) as u8);
    }
    if payload.is_empty() || payload.len() > PAYLOAD_LIMIT {
        return Err("fixture aggregate exceeds payload bound".into());
    }
    Ok(payload)
}

fn verify(payload: &[u8], batch: &[Message]) -> Result<()> {
    let mut offset = 0;
    for message in batch {
        let end = offset + FRAME_HEADER + message.bytes;
        let part = payload.get(offset..end).ok_or("truncated fixture echo")?;
        if part[..4] != message.id.to_be_bytes()
            || part[4..8] != (message.bytes as u32).to_be_bytes()
            || part[8..]
                .iter()
                .any(|byte| *byte != (message.id % 251) as u8)
        {
            return Err("fixture constituent mismatch".into());
        }
        offset = end;
    }
    if offset != payload.len() {
        return Err("extra fixture echo bytes".into());
    }
    Ok(())
}

#[derive(Serialize)]
struct Completion {
    id: u32,
    producer: usize,
    kind: Kind,
    bytes: usize,
    latency_us: u64,
    queue_us: u64,
    service_us: u64,
}

async fn measure(name: &str, variant: Variant, quick: bool) -> Result<serde_json::Value> {
    let fixture = Fixture::new(100, 0)
        .await
        .map_err(|error| format!("fixture setup: {error}"))?;
    let client = Arc::new(
        fixture
            .client(true)
            .map_err(|error| format!("client setup: {error}"))?,
    );
    let warming = Instant::now();
    client
        .warm(fixture.terminal, fixture.terminal_pin)
        .await
        .map_err(|error| format!("client warm-up: {error}"))?;
    let warm_us = warming.elapsed().as_micros() as u64;
    let offered = workload(name, quick);
    let producers = if name == "four_producers" { 4 } else { 1 };
    let mut queue = FairQueue::new(producers);
    let mut next = 0;
    let mut pending = JoinSet::new();
    let mut completions = Vec::new();
    let mut rejected = Vec::new();
    let mut batches = 0;
    let mut encoded_bytes = 0;
    let mut cell_wire_bytes = 0;
    let mut inflight = 0;
    let mut peak_buffer = 0;
    let mut peak_jobs = 0;
    let start = Instant::now();
    let (cpu_start, _) = resources();
    for trace in &fixture.traces {
        trace.lock().unwrap().start = Some(start);
    }
    while next < offered.len() || queue.jobs > 0 || !pending.is_empty() {
        let now = start.elapsed().as_micros() as u64;
        while next < offered.len() && offered[next].at_us <= now {
            let message = offered[next].clone();
            if !queue.push(message.clone()) {
                rejected.push(message.id);
            }
            next += 1;
        }
        peak_buffer = peak_buffer.max(queue.bytes + inflight);
        peak_jobs = peak_jobs.max(queue.jobs);
        while pending.len() < variant.window {
            let Some(batch) = queue.pop(variant.packing) else {
                break;
            };
            let useful: usize = batch.iter().map(|message| message.bytes).sum();
            let payload = encode(&batch)?;
            encoded_bytes += payload.len();
            let wire = Cell::new(CellType::Msg, 0, batches as u16, payload).encode_wire()?;
            cell_wire_bytes += wire.len();
            batches += 1;
            inflight += useful;
            let queued_us = start.elapsed().as_micros() as u64;
            let client = client.clone();
            let target = fixture.terminal;
            let pin = fixture.terminal_pin;
            pending.spawn(async move {
                let dispatched = Instant::now();
                let outcome = client
                    .post_cell_pinned(target, pin, "performance-fixture", Bytes::from(wire))
                    .await
                    .map_err(|error| format!("echo request: {error}"))?;
                let HopOutcome::Accepted(Some(reply)) = outcome else {
                    return Err("fixture echo rejected".into());
                };
                verify(&reply.payload, &batch)
                    .map_err(|error| format!("echo validation: {error}"))?;
                let service_us = dispatched.elapsed().as_micros() as u64;
                Ok::<_, Error>((batch, queued_us, service_us))
            });
        }
        let ready = if pending.is_empty() {
            if next < offered.len() {
                tokio::time::sleep_until(
                    (start + Duration::from_micros(offered[next].at_us)).into(),
                )
                .await;
            }
            None
        } else if next < offered.len() {
            tokio::select! {
                result = pending.join_next() => result,
                _ = tokio::time::sleep_until((start + Duration::from_micros(offered[next].at_us)).into()) => None,
            }
        } else {
            pending.join_next().await
        };
        if let Some(result) = ready {
            let (batch, dispatched_us, service_us) = result??;
            let completed_us = start.elapsed().as_micros() as u64;
            for message in batch {
                inflight -= message.bytes;
                completions.push(Completion {
                    id: message.id,
                    producer: message.producer,
                    kind: message.kind,
                    bytes: message.bytes,
                    latency_us: completed_us - message.at_us,
                    queue_us: dispatched_us - message.at_us,
                    service_us,
                });
            }
        }
    }
    let transfer_us = start.elapsed().as_micros() as u64;
    let minimum = Duration::from_secs(if quick { 2 } else { 8 });
    if let Some(remaining) = minimum.checked_sub(start.elapsed()) {
        tokio::time::sleep(remaining).await;
    }
    let (cpu_end, peak_rss) = resources();
    let observers: Vec<_> = fixture.traces.iter().enumerate().map(|(index, trace)| {
        let mut trace = trace.lock().unwrap();
        trace.start = None;
        json!({"fixture_link": index, "bytes": trace.bytes, "samples": trace.samples, "dropped": trace.dropped,
            "connections_including_warmup": trace.connections})
    }).collect();
    let measurement_us = start.elapsed().as_micros() as u64;
    assert_eq!(completions.len() + rejected.len(), offered.len());
    assert_eq!(inflight + queue.bytes, 0);
    Ok(
        json!({"offered": offered, "completions": completions, "rejected_ids": rejected,
        "transfer_us": transfer_us, "measurement_us": measurement_us, "warm_us": warm_us,
        "batches": batches, "encoded_payload_bytes": encoded_bytes, "request_cell_wire_bytes": cell_wire_bytes,
        "peak_buffered_payload_bytes": peak_buffer, "peak_queued_messages": peak_jobs,
        "process_cpu_us": cpu_end.saturating_sub(cpu_start), "process_lifetime_peak_rss_kib": peak_rss,
        "observers": observers, "admission_wait_us": null, "application_schedule": "transport_only",
        "added_packing_delay_us": 0}),
    )
}

pub(super) async fn run(path: &std::path::Path, quick: bool) -> Result<()> {
    if path.exists() || path.is_symlink() {
        return Err("refusing to overwrite evidence".into());
    }
    let mut trials = Vec::new();
    let mut failed = false;
    for repeat in 0..if quick { 1 } else { 5 } {
        for name in SCENARIOS {
            // Rotate order across the matrix (first-position counts differ by
            // at most one), without changing security randomness.
            let rotation = (repeat + SCENARIOS.iter().position(|item| *item == name).unwrap()) % 4;
            for position in 0..4 {
                let variant = VARIANTS[(position + rotation) % 4];
                let (started_unix, preflight_wait_us, deferred) = await_credential_window().await;
                let expires_unix = started_unix + CREDENTIAL_EPOCH_SECONDS
                    - started_unix % CREDENTIAL_EPOCH_SECONDS;
                eprintln!("utilization {name} {} repeat {repeat}", variant.name);
                let mut trial = match tokio::time::timeout(
                    Duration::from_secs(TRIAL_TIMEOUT_SECONDS),
                    measure(name, variant, quick),
                )
                .await
                {
                    Ok(Ok(value)) => value,
                    Ok(Err(error)) => {
                        failed = true;
                        // This fixture generates all traffic locally. Keep a bounded
                        // diagnostic, without recording request or response bodies.
                        let detail: String = error.to_string().chars().take(512).collect();
                        eprintln!(
                            "utilization failure {name} {} repeat {repeat}: {detail}",
                            variant.name
                        );
                        json!({"error": "fixture_failed", "error_detail": detail})
                    }
                    Err(_) => {
                        failed = true;
                        eprintln!(
                            "utilization timeout {name} {} repeat {repeat}",
                            variant.name
                        );
                        json!({"error": "timeout"})
                    }
                };
                trial["credential_started_unix"] = json!(started_unix);
                trial["credential_expires_unix"] = json!(expires_unix);
                trial["finished_unix"] = json!(now_unix());
                trial["preflight_wait_us"] = json!(preflight_wait_us);
                trial["preflight_deferred"] = json!(deferred);
                trial["scenario"] = json!(name);
                trial["repeat"] = json!(repeat);
                trial["order"] = json!(position);
                trial["variant"] = json!(variant);
                trial["workload_sha256"] = json!(format!(
                    "{:x}",
                    Sha256::digest(serde_json::to_vec(&json!(workload(name, quick)))?)
                ));
                trials.push(trial);
            }
        }
    }
    let report = json!({"schema": 2, "kind": "loopback_utilization_study", "quick": quick,
        "payload": "generated_non_executable_bytes", "privacy_verdict": "not_qualified",
        "sample_unit": "tcp_read_chunk_not_packet", "carrier_slot_ms": 100,
        "carrier_record_bytes": 4096, "logical_producers_share_one_client": true,
        "payload_limit": PAYLOAD_LIMIT, "queue_limit": QUEUE_LIMIT, "job_limit": JOB_LIMIT,
        "trial_timeout_seconds": TRIAL_TIMEOUT_SECONDS, "trials": trials,
        "credential_epoch_seconds": CREDENTIAL_EPOCH_SECONDS,
        "credential_control": "defer_before_fixture_until_lifetime_exceeds_trial_deadline"});
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(file.as_file_mut(), &report)?;
    file.write_all(b"\n")?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)?;
    if failed {
        return Err("utilization trials incomplete; evidence retained".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_window_matches_service_expiry_and_defers_the_whole_deadline() {
        let service = RelayService::new(
            "127.0.0.2:12345".parse().unwrap(),
            [1; 32],
            [2; 32],
            Arc::new(Directory::new()),
            ServicePolicy::default(),
        )
        .unwrap();
        for (now, wait) in [
            (7200, 0),
            (10_679, 0),
            (10_680, 121),
            (10_799, 2),
            (10_800, 0),
        ] {
            let before = service.introduction(now);
            assert_eq!(credential_wait_seconds(now), wait);
            assert_eq!(before.expires_at, now + 3600 - now % 3600);
            let admitted_at = now + wait;
            let ready = service.introduction(admitted_at);
            assert!(ready.expires_at - admitted_at > TRIAL_TIMEOUT_SECONDS);
            if wait != 0 {
                assert_ne!(before.circuit_cap, ready.circuit_cap);
                assert_eq!(before.reentry_cap, ready.reentry_cap);
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "bounded diagnostic replay; never replaces failed comparison evidence"]
    async fn packing_chat_bulk_diagnostic() {
        for repeat in 0..3 {
            let trial = tokio::time::timeout(
                Duration::from_secs(120),
                measure("chat_bulk", VARIANTS[2], false),
            )
            .await
            .expect("diagnostic trial timeout")
            .unwrap_or_else(|error| panic!("diagnostic repeat {repeat}: {error}"));
            assert!(trial["rejected_ids"].as_array().unwrap().is_empty());
            assert_eq!(trial["completions"].as_array().unwrap().len(), 36);
            eprintln!("diagnostic repeat {repeat}: 36 validated echoes");
        }
    }

    fn message(id: u32, producer: usize, kind: Kind, bytes: usize) -> Message {
        Message {
            id,
            producer,
            kind,
            at_us: 0,
            bytes,
        }
    }

    #[test]
    fn packing_preserves_constituents_and_detects_corruption_order_and_truncation() {
        let batch = vec![
            message(1, 0, Kind::Chat, 128),
            message(2, 0, Kind::Chat, 256),
        ];
        let payload = encode(&batch).unwrap();
        verify(&payload, &batch).unwrap();
        assert!(verify(&payload[..payload.len() - 1], &batch).is_err());
        assert!(verify(&payload, &[batch[1].clone(), batch[0].clone()]).is_err());
        let mut corrupt = payload.clone();
        corrupt[8] ^= 1;
        assert!(verify(&corrupt, &batch).is_err());
        let mut extra = payload;
        extra.push(0);
        assert!(verify(&extra, &batch).is_err());
    }

    #[test]
    fn round_robin_preserves_sender_class_and_fifo_with_or_without_packing() {
        for packing in [false, true] {
            let mut queue = FairQueue::new(2);
            for item in [
                message(1, 0, Kind::Chat, 128),
                message(2, 0, Kind::Chat, 128),
                message(3, 0, Kind::Bulk, 11992),
                message(4, 1, Kind::Chat, 128),
                message(5, 1, Kind::Bulk, 11992),
            ] {
                assert!(queue.push(item));
            }
            let first = queue.pop(packing).unwrap();
            assert_eq!(
                first.iter().map(|m| m.id).collect::<Vec<_>>(),
                if packing { vec![1, 2] } else { vec![1] }
            );
            assert_eq!(queue.pop(packing).unwrap()[0].id, 4);
            assert_eq!(queue.pop(packing).unwrap()[0].id, 3);
            assert_eq!(queue.pop(packing).unwrap()[0].id, 5);
        }
    }

    #[test]
    fn packing_never_waits_and_stops_at_the_existing_payload_limit() {
        let mut queue = FairQueue::new(1);
        assert!(queue.pop(true).is_none());
        queue.push(message(0, 0, Kind::Chat, 128));
        assert_eq!(queue.pop(true).unwrap().len(), 1);
        for id in 1..101 {
            queue.push(message(id, 0, Kind::Chat, 128));
        }
        let first = queue.pop(true).unwrap();
        assert_eq!(first.len(), PAYLOAD_LIMIT / 136);
        assert!(encode(&first).unwrap().len() <= PAYLOAD_LIMIT);
        assert_eq!(queue.pop(true).unwrap().len(), 100 - first.len());
        assert_eq!(queue.bytes, 0);
        assert!(encode(&[message(999, 0, Kind::Chat, PAYLOAD_LIMIT)]).is_err());
    }

    #[test]
    fn overloaded_queues_reject_new_work_without_losing_accepted_work() {
        let mut queue = FairQueue::new(1);
        let mut count = 0;
        while queue.push(message(count, 0, Kind::Bulk, 11992)) {
            count += 1;
        }
        assert!(queue.bytes <= QUEUE_LIMIT);
        let mut popped = 0;
        while let Some(batch) = queue.pop(true) {
            popped += batch.len();
        }
        assert_eq!(popped, count as usize);
        assert_eq!(queue.bytes, 0);
        for id in 0..JOB_LIMIT {
            assert!(queue.push(message(id as u32, 0, Kind::Chat, 1)));
        }
        assert!(!queue.push(message(9999, 0, Kind::Chat, 1)));
    }

    #[tokio::test]
    async fn observed_copy_retains_delayed_bytes_and_propagates_disconnect() {
        let (mut sender, read) = tokio::io::duplex(16);
        let (write, mut receiver) = tokio::io::duplex(4);
        let trace = Arc::new(Mutex::new(Trace {
            start: Some(Instant::now()),
            ..Trace::default()
        }));
        let task = tokio::spawn(copy_observed(read, write, trace.clone(), 0, 5));
        sender.write_all(b"fixture").await.unwrap();
        sender.shutdown().await.unwrap();
        // The smaller destination fills before its consumer starts reading.
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert!(!task.is_finished());
        let mut result = Vec::new();
        receiver.read_to_end(&mut result).await.unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(&result, b"fixture");
        assert_eq!(trace.lock().unwrap().bytes[0], 7);
        let (mut sender, read) = tokio::io::duplex(16);
        let (write, receiver) = tokio::io::duplex(16);
        drop(receiver);
        let task = tokio::spawn(copy_observed(read, write, trace, 0, 0));
        sender.write_all(b"fixture").await.unwrap();
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn cancelling_a_trial_releases_its_loopback_listeners() {
        let (ready, receive) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let fixture = Fixture::new(100, 0).await.unwrap();
            ready.send(fixture.terminal).unwrap();
            std::future::pending::<()>().await;
        });
        let address = receive.await.unwrap();
        assert!(TcpStream::connect(address).await.is_ok());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), async {
            while TcpStream::connect(address).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
    }
}
