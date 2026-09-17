use gcoms_node::node::{start, NodeConfig};
use std::net::{SocketAddr, TcpListener};

fn unused_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_releases_listen_address() {
    let addr = unused_addr();
    let config = |seed| NodeConfig {
        seed: [seed; 32],
        listen: addr,
        control: None,
        advertise: None,
        inbox_relay: None,
        profile: gcoms_node::node::NodeProfile::fixture(),
        alias_lifecycle: Default::default(),
    };

    let first = start(config(1)).await.expect("start first node");
    first.shutdown().await;

    let second = start(config(2))
        .await
        .expect("restart on the same listen address");
    second.shutdown().await;
}
