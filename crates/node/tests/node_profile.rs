use gcoms_node::node::{start, NodeConfig, NodeProfile};

fn config(listen: &str, profile: NodeProfile) -> NodeConfig {
    NodeConfig {
        seed: [0x51; 32],
        listen: listen.parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: None,
        profile,
        alias_lifecycle: Default::default(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn production_loopback_is_outbound_only_and_locally_ready() {
    let node = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        start(config("127.0.0.1:0", NodeProfile::Production)),
    )
    .await
    .expect("local startup must not await a network")
    .expect("production can bind a private listener");
    assert!(
        node.info.aliases.is_empty(),
        "a private listener is never advertised as an inbox"
    );
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn fixture_profile_refuses_public_listener() {
    // 0.0.0.0 is allowed (it may be a container); a concrete non-loopback
    // address is not.
    let error = start(config("192.0.2.10:0", NodeProfile::fixture()))
        .await
        .err()
        .expect("fixture on a routable address must be refused");
    assert!(error.contains("fixture"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn fixture_profile_runs_on_loopback() {
    let handle = start(config("127.0.0.1:0", NodeProfile::fixture()))
        .await
        .expect("fixture starts");
    handle.shutdown().await;
}
