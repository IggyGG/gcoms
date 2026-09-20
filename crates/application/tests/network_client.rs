#![cfg(all(feature = "network-client", feature = "embedded", feature = "files"))]

use base64::Engine;
use gcoms::{
    sdk::{self, sharing::Scope},
    Application, Backend,
};
use std::{path::Path, time::Duration};

fn builder(path: &Path, name: &str) -> gcoms::ApplicationBuilder {
    Application::builder(name)
        .profile(path)
        .unlock_secret("client-fixture-secret")
        .local_fixture()
}

async fn provision(host: &Application) -> sdk::RelayCard {
    let card = host
        .embedded_runtime()
        .unwrap()
        .sdk_client()
        .embedded()
        .node()
        .provision_client_relay()
        .await
        .unwrap();
    sdk::RelayCard(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(card.encode_private().unwrap())
            .into_bytes(),
    )
}

#[tokio::test]
async fn outbound_clients_use_remote_inboxes_and_reopen_files_and_identity() {
    let directory = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(directory.path(), true).unwrap();
    let host = builder(&directory.path().join("host"), "host")
        .open()
        .await
        .unwrap();
    let a_card = provision(&host).await;
    let b_card = provision(&host).await;
    let a_path = directory.path().join("alice");
    let open_alice = || {
        builder(&a_path, "alice")
            .backend(Backend::NetworkClient)
            .relay(Some(a_card.clone()))
    };
    let alice = open_alice().open().await.unwrap();
    let bob = builder(&directory.path().join("bob"), "bob")
        .backend(Backend::NetworkClient)
        .relay(Some(b_card))
        .open()
        .await
        .unwrap();
    for app in [&alice, &bob] {
        let client = app.embedded_runtime().unwrap().sdk_client().embedded();
        assert_eq!(client.node().listener_addr().port(), 0);
        assert!(client.node().provision_client_relay().await.is_err());
        assert_eq!(client.node().diagnostics().relay_resources.jobs, 0);
        assert_eq!(client.node().diagnostics().relay_resources.bytes, 0);
    }
    let peer = bob.peer().await.unwrap();
    alice
        .messaging()
        .submit_durable_opaque(&peer.contact, "test.message", b"outbound hello")
        .await
        .unwrap();
    let delivery = tokio::time::timeout(Duration::from_secs(15), bob.receive())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delivery.message.body, b"outbound hello");
    delivery.acknowledge().await.unwrap();

    let channel = alice
        .messaging()
        .create_channel("mobile", "alice", 8, sdk::ChannelVisibility::Private)
        .await
        .unwrap();
    let invitation = alice
        .messaging()
        .create_channel_invitation("mobile", 3600)
        .await
        .unwrap();
    bob.messaging()
        .join_channel_invitation(&invitation.link, "bob", 20)
        .await
        .unwrap();
    assert_eq!(
        alice
            .messaging()
            .channel_roster("mobile")
            .await
            .unwrap()
            .len(),
        2
    );
    bob.messaging()
        .send_channel("mobile", b"mobile channel")
        .await
        .unwrap();

    let source = vec![0x74; 256 * 1024 + 19];
    let id = alice
        .files()
        .import(
            Scope {
                channel: channel.0,
                participants: vec![],
            },
            "mobile.bin".into(),
            source.len() as u64,
            &mut source.as_slice(),
        )
        .await
        .unwrap();
    let safety = alice.identity().safety_number;
    alice.close().await.unwrap();
    let alice = open_alice().open().await.unwrap();
    assert_eq!(alice.identity().safety_number, safety);
    let mut restored = Vec::new();
    alice.files().export(id, &mut restored).await.unwrap();
    assert_eq!(restored, source);
    let target = directory.path().join("export.bin");
    alice.files().save_path(id, &target).await.unwrap();
    assert!(alice.files().save_path(id, &target).await.is_err());
    alice.close().await.unwrap();
    bob.close().await.unwrap();
    host.close().await.unwrap();
}

#[tokio::test]
async fn outbound_clients_reject_listener_configuration() {
    let directory = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(directory.path(), true).unwrap();
    let error = builder(&directory.path().join("client"), "client")
        .backend(Backend::NetworkClient)
        .listen("127.0.0.1:4567".parse().unwrap())
        .open()
        .await
        .err()
        .unwrap();
    assert!(
        error.contains("outbound clients cannot configure listeners"),
        "{error}"
    );
}
