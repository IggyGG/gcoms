#![cfg(feature = "push-gateway")]
use gcoms_node::{
    node::{start, NodeConfig, NodeHandle, NodeProfile},
    push_notifications::{GatewayConfig, PushPlatform, PushRegistrationRequest},
};

async fn node(seed: u8, inbox_relay: Option<gcoms_node::proto::NodeInfo>) -> NodeHandle {
    start(NodeConfig {
        seed: [seed; 32],
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay,
        profile: NodeProfile::fixture(),
        alias_lifecycle: Default::default(),
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn real_owned_inbox_can_register_and_bind_notifications() {
    let relay = node(91, None).await;
    relay
        .configure_push_gateway(GatewayConfig {
            url: "https://push.invalid/v1/events".into(),
            relay_id: "fixture".into(),
            key: [42; 32],
            apps: vec!["boo.gchat.app".into()],
        })
        .await
        .unwrap();
    let client = node(92, Some(relay.provision_client_relay().await.unwrap())).await;
    let ticket = client
        .request_push_registration(PushRegistrationRequest {
            app_id: "boo.gchat.app".into(),
            installation_nonce: [7; 32],
            platform: PushPlatform::Fcm,
            token: "fixture-provider-token".into(),
            revision: 1,
            visible: true,
        })
        .await
        .expect("authenticated ticket over the actual administrative transport");
    assert_eq!(ticket.gateway_origin, "https://push.invalid");
    assert!(!ticket.ticket.is_empty());
    client
        .bind_push_notifications([9; 32], 2, ticket.expires)
        .await
        .unwrap();
    client
        .bind_push_notifications([0; 32], 3, ticket.expires)
        .await
        .unwrap();
    client.shutdown().await;
    relay.shutdown().await;
}
