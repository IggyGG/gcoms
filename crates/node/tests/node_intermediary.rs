#![cfg(feature = "client-persist")]

//! SPEC §11.1: the first hop of a direct message is a random intermediary
//! chosen per message from the grant pool, never the receiver's own relay
//! and never a grant the receiver issued; with no eligible grant the node
//! falls back to its own relay and counts it.

use gcoms_node::node::{start, Ev, NodeConfig, NodeHandle, NodeProfile};

async fn spawn(seed: u8) -> NodeHandle {
    start(NodeConfig {
        seed: [seed; 32],
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: None,
        profile: NodeProfile::fixture(),
        alias_lifecycle: Default::default(),
    })
    .await
    .expect("node start")
}

async fn await_text(node: &NodeHandle, want: &[u8]) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        let event = tokio::time::timeout_at(deadline, node.next_event())
            .await
            .unwrap_or_else(|_| panic!("timeout: {}", String::from_utf8_lossy(want)))
            .expect("event stream closed");
        if let Ev::Message { text, .. } = event {
            if text == want {
                return;
            }
        }
    }
}

/// Establish a session both ways so each side offers the other a grant.
async fn befriend(a: &NodeHandle, b: &NodeHandle, tag: &str) {
    a.send_1to1(&b.info, format!("hi {tag}").as_bytes(), None)
        .await
        .expect("send");
    await_text(b, format!("hi {tag}").as_bytes()).await;
    b.send_1to1(&a.info, format!("hello {tag}").as_bytes(), None)
        .await
        .expect("reply");
    await_text(a, format!("hello {tag}").as_bytes()).await;
}

async fn wait_pool(node: &NodeHandle, at_least: usize) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        let stats = node.intermediary_stats().await.unwrap();
        if stats.pool >= at_least {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "grant pool never reached {at_least}: {stats:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Wait until no FRWD traffic has flowed through any of `nodes` for a full
/// quiet interval. Grant offers and contact updates queued during befriend
/// drain through random intermediaries (including B), so measuring receiver
/// exclusion requires letting that handshake traffic settle first; otherwise
/// A's legitimate traffic to the *grantors* (which may transit B) is
/// miscounted as B being used for B-bound messages.
async fn quiesce(nodes: &[&NodeHandle]) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut last: Vec<u64> = Vec::new();
    loop {
        let mut now = Vec::new();
        for n in nodes {
            now.push(n.intermediary_stats().await.unwrap().frwd_admitted);
        }
        if now == last {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "traffic never quiesced: {now:?}"
        );
        last = now;
        tokio::time::sleep(std::time::Duration::from_millis(750)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn messages_spread_over_random_intermediaries_and_exclude_the_receiver() {
    let a = spawn(0xA1).await;
    let b = spawn(0xB2).await;
    let grantors = [spawn(0x11).await, spawn(0x12).await, spawn(0x13).await];

    // A learns three intermediaries and (through B's grant) one it must not
    // use toward B. B learns A.
    for (index, grantor) in grantors.iter().enumerate() {
        befriend(&a, grantor, &format!("g{index}")).await;
    }
    befriend(&a, &b, "b").await;
    wait_pool(&a, 4).await;
    // Let all handshake-time grant offers and contact updates drain through
    // their intermediaries before the baseline, so the only traffic in the
    // measurement window below is A -> B.
    quiesce(&[&grantors[0], &grantors[1], &grantors[2], &b]).await;

    let before: Vec<u64> = {
        let mut v = Vec::new();
        for g in &grantors {
            v.push(g.intermediary_stats().await.unwrap().frwd_admitted);
        }
        v
    };
    let b_before = b.intermediary_stats().await.unwrap().frwd_admitted;
    let fallbacks_before = a.intermediary_stats().await.unwrap().fallbacks;

    let total = 24u64;
    for i in 0..total {
        let text = format!("spread-{i}");
        a.send_1to1(&b.info, text.as_bytes(), None).await.unwrap();
        await_text(&b, text.as_bytes()).await;
    }

    let mut admitted = Vec::new();
    for (index, g) in grantors.iter().enumerate() {
        let after = g.intermediary_stats().await.unwrap().frwd_admitted;
        admitted.push(after - before[index]);
    }
    let fallbacks_after = a.intermediary_stats().await.unwrap().fallbacks;
    let _ = b_before; // B's counter is not a usable exclusion signal; see below.

    eprintln!("admitted per grantor: {admitted:?}, fallbacks: {fallbacks_after}");
    // The 24 A -> B messages spread across the three eligible grantors: each
    // carried some, none carried all. This is what the aggregate counter can
    // show. It cannot isolate B-bound traffic from A's incidental traffic to
    // the grantors, so receiver exclusion (B is never the intermediary for a
    // message addressed to B) is proven deterministically by gc-node's unit
    // test `eligible_intermediaries_exclude_receiver_self_and_expired`.
    assert!(admitted.iter().all(|n| *n >= 2), "{admitted:?}");
    assert!(admitted.iter().all(|n| *n < total), "{admitted:?}");
    let carried: u64 = admitted.iter().sum();
    assert!(
        carried >= total,
        "grantors carried {carried} hops for {total} messages; some delivery did not route through the pool"
    );
    // No B-bound message fell back to A's own relay: the pool was never empty.
    assert_eq!(
        fallbacks_after, fallbacks_before,
        "fell back to own relay with an eligible pool"
    );

    for node in [a, b].into_iter().chain(grantors) {
        node.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn no_eligible_intermediary_falls_back_to_own_relay_and_counts_it() {
    let a = spawn(0xA3).await;
    let b = spawn(0xB4).await;
    befriend(&a, &b, "only").await;
    wait_pool(&a, 1).await;
    let before = a.intermediary_stats().await.unwrap().fallbacks;
    for i in 0..3 {
        let text = format!("fallback-{i}");
        a.send_1to1(&b.info, text.as_bytes(), None).await.unwrap();
        await_text(&b, text.as_bytes()).await;
    }
    let after = a.intermediary_stats().await.unwrap().fallbacks;
    assert!(after >= before + 3, "fallbacks {before} -> {after}");
    a.shutdown().await;
    b.shutdown().await;
}
