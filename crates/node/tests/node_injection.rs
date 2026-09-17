//! Malformed-cell injection against a live node's relay endpoints.
//!
//! Asserts the black-box invariants a friend's relay must hold when a peer (or
//! a network attacker) posts garbage at it: every malformed post is rejected
//! uniformly as the decoy 404 (never a panic, never a distinguishing status),
//! the node stays responsive throughout, and a well-formed 1:1 message still
//! delivers afterward. The internal parking/queue bounds are proven separately
//! by the lib-level unit tests in `channel.rs`/`queues.rs`/`scheduler.rs`; this
//! file complements them from outside the `NodeHandle` API.

use gcoms_core::{Cell, CellType};
use gcoms_node::node::{start, Ev, NodeConfig, NodeHandle, NodeProfile};
use gcoms_transport::{HopOutcome, Tp1Client};

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
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let event = tokio::time::timeout_at(deadline, node.next_event())
            .await
            .unwrap_or_else(|_| panic!("timeout waiting for {}", String::from_utf8_lossy(want)))
            .expect("event stream closed");
        if let Ev::Message { text, .. } = event {
            if text == want {
                return;
            }
        }
    }
}

/// Post one raw wire cell at a relay endpoint and return the transport outcome.
async fn post_raw(
    client: &Tp1Client,
    target_addr: std::net::SocketAddr,
    service_id: [u8; 32],
    path: &str,
    cell: Cell,
) -> HopOutcome {
    let wire = cell.encode_wire().expect("encode wire");
    client
        .post_cell_pinned(target_addr, service_id, path, bytes::Bytes::from(wire))
        .await
        .expect("transport round-trip")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_cells_are_rejected_uniformly_and_the_node_stays_live() {
    let relay = spawn(0x71).await;
    let sender = spawn(0x72).await;

    // A valid FRWD provisioning path on the relay: the authenticated endpoint
    // most exposed to peers. Malformed bodies posted here must decoy-404.
    let card = relay
        .provision_client_relay()
        .await
        .expect("relay provisioning card");
    let provision = card.provisioning.as_ref().expect("private provision");
    let frwd_target = provision.aliases[0].contact.target.clone();
    let frwd_path = provision.frwd_path.clone();

    let client = Tp1Client::new().expect("client");

    // A spread of malformed cells at the FRWD endpoint: wrong inner type,
    // truncated bodies, an all-zero body, and each hop cell type carrying junk.
    let garbage: Vec<Cell> = vec![
        Cell::new(CellType::Frwd, 0, 0, vec![0; 32]),
        Cell::new(CellType::Frwd, 0, 0, vec![0xAB; 4]),
        Cell::new(CellType::Frwd, 0, 0, Vec::new()),
        Cell::new(CellType::Frwd, 0, 0, vec![0xFF; 4096]),
        Cell::new(CellType::RelayPush, 0, 0, vec![0x11; 64]),
        Cell::new(CellType::Pex, 0, 0, vec![0x22; 40]),
        Cell::new(CellType::Msg, 0, 0, vec![0x33; 96]),
        Cell::new(CellType::Ack, 0, 0, vec![1, 2, 3]),
        Cell::new(CellType::Cover, 0, 0, vec![0x44; 16]),
    ];

    for (i, cell) in garbage.into_iter().enumerate() {
        let outcome = post_raw(
            &client,
            frwd_target.address,
            frwd_target.relay_service_id,
            &frwd_path,
            cell,
        )
        .await;
        assert_eq!(
            outcome,
            HopOutcome::Decoy(404),
            "malformed cell #{i} did not decoy-404"
        );
    }

    // Junk at an unknown path is also the decoy, disclosing nothing.
    let outcome = post_raw(
        &client,
        frwd_target.address,
        frwd_target.relay_service_id,
        "this-path-does-not-exist",
        Cell::new(CellType::Frwd, 0, 0, vec![0x55; 128]),
    )
    .await;
    assert_eq!(
        outcome,
        HopOutcome::Decoy(404),
        "unknown path leaked a status"
    );

    // The relay is still responsive after the barrage.
    relay
        .current_info()
        .await
        .expect("relay still answers current_info after injection");

    // And a well-formed 1:1 message still delivers end to end.
    let relay_info = relay.current_info().await.expect("relay info");
    sender
        .send_1to1(&relay_info, b"still alive after injection", None)
        .await
        .expect("send 1to1");
    await_text(&relay, b"still alive after injection").await;

    sender.shutdown().await;
    relay.shutdown().await;
}
