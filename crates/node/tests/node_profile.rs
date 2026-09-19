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

#[cfg(feature = "experimental-gc2")]
#[tokio::test(flavor = "multi_thread")]
async fn gc2_carrier_fixture_starts_and_stops_with_an_in_memory_directory() {
    let handle = start(config(
        "127.0.0.1:0",
        NodeProfile::gc2_carrier_fixture(None, 1),
    ))
    .await
    .expect("GC/2 carrier fixture starts");
    handle.shutdown().await;
    drop(handle);
}

#[cfg(feature = "experimental-gc2")]
#[tokio::test(flavor = "multi_thread")]
async fn gc2_carrier_production_profile_starts_and_restores_its_directory() {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let make = |seed: [u8; 32]| NodeConfig {
        seed,
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: None,
        profile: NodeProfile::gc2_carrier_production(Some(dir.path().to_path_buf()), 1),
        alias_lifecycle: Default::default(),
    };
    assert!(NodeProfile::gc2_carrier_production(None, 1).is_production());
    assert!(NodeProfile::gc2_carrier_qualification(None, 1, 7).is_production());
    let first = start(make([0x53; 32]))
        .await
        .expect("production carrier starts");
    first.shutdown().await;
    drop(first);
    let second = start(make([0x53; 32]))
        .await
        .expect("same identity restores the directory");
    second.shutdown().await;
    drop(second);
    let error = start(make([0x54; 32]))
        .await
        .err()
        .expect("another identity must not open the directory");
    assert!(!error.is_empty());
}

#[cfg(feature = "experimental-gc2")]
#[tokio::test(flavor = "multi_thread")]
async fn gc2_carrier_fixture_restores_its_directory_and_refuses_a_wrong_seed() {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let make = |seed: [u8; 32]| NodeConfig {
        seed,
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: None,
        profile: NodeProfile::gc2_carrier_fixture(Some(dir.path().to_path_buf()), 1),
        alias_lifecycle: Default::default(),
    };
    let first = start(make([0x51; 32])).await.expect("first carrier start");
    first.shutdown().await;
    drop(first);
    let second = start(make([0x51; 32]))
        .await
        .expect("same identity restores the directory");
    second.shutdown().await;
    drop(second);
    let error = start(make([0x52; 32]))
        .await
        .err()
        .expect("another identity must not open the directory");
    assert!(!error.is_empty());
}
