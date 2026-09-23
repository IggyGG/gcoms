#![cfg(all(feature = "embedded", feature = "ipc"))]

use gcoms::{
    sdk::{component::RoutePermission, component::RoutingPolicy, GcClient},
    Application,
};

#[tokio::test]
async fn central_host_preserves_chat_identity_and_excludes_scoped_inbox_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    gcoms::sdk::private_fs::make_private(dir.path(), true).unwrap();
    let path = dir.path().join("profile");
    let open = || {
        Application::builder("chat-with-fleet")
            .profile(&path)
            .unlock_secret("fixture-passphrase")
            .local_fixture()
            .receive_messages(false)
    };
    let original = open().create(true).open().await.unwrap();
    let identity = original.identity();
    let public_key = original
        .messaging()
        .contact_identity(&identity.contact_card)
        .unwrap();
    original.close().await.unwrap();
    let policy = RoutingPolicy {
        components: vec![[1; 16], [2; 16]],
        bootstrap_listeners: Vec::new(),
        routes: vec![
            RoutePermission {
                local: [1; 16],
                remote: [2; 16],
                peer_identity: public_key.clone(),
                content_types: vec!["fleet.test".into()],
            },
            RoutePermission {
                local: [2; 16],
                remote: [1; 16],
                peer_identity: public_key,
                content_types: vec!["fleet.test".into()],
            },
        ],
    };
    assert!(open()
        .create(false)
        .central_components(policy.clone(), vec![[1; 16]], "wrong identity".into())
        .open()
        .await
        .is_err());
    // Refusing a wrong pin must not convert the personal profile.
    open()
        .create(false)
        .open()
        .await
        .unwrap()
        .close()
        .await
        .unwrap();
    let host = open()
        .create(false)
        .central_components(
            policy.clone(),
            vec![[1; 16]],
            identity.safety_number.clone(),
        )
        .open()
        .await
        .unwrap();
    assert_eq!(host.identity().safety_number, identity.safety_number);
    let wire = gcoms::sdk::component::RoutedApplication {
        source: [1; 16],
        destination: [2; 16],
        application: gcoms::sdk::ApplicationMessage {
            content_type: "fleet.test".into(),
            body: b"private component work".to_vec(),
        }
        .encode()
        .unwrap(),
    }
    .encode()
    .unwrap();
    let node = host
        .embedded_runtime()
        .unwrap()
        .sdk_client()
        .embedded()
        .node()
        .clone();
    node.submit_local_component(&wire).await.unwrap();
    let scoped = host
        .embedded_runtime()
        .unwrap()
        .sdk_client()
        .application_inbox(0, 32)
        .await
        .unwrap();
    assert_eq!(scoped.len(), 1);
    assert!(host
        .messaging()
        .application_inbox(0, 32)
        .await
        .unwrap()
        .is_empty());
    assert!(host
        .messaging()
        .commit_application(scoped[0].sequence, scoped[0].receipt_digest)
        .await
        .is_err());
    let hidden = scoped[0].clone();
    drop(node);
    host.close().await.unwrap();

    assert!(open().create(false).open().await.is_err());
    let reopened = open()
        .create(false)
        .central_components(policy, vec![[1; 16]], identity.safety_number.clone())
        .open()
        .await
        .unwrap();
    assert_eq!(reopened.identity().safety_number, identity.safety_number);
    assert!(reopened
        .messaging()
        .application_inbox(0, 32)
        .await
        .unwrap()
        .is_empty());
    let scoped = reopened.embedded_runtime().unwrap().sdk_client();
    assert_eq!(
        scoped.application_inbox(0, 32).await.unwrap()[0].receipt_digest,
        hidden.receipt_digest
    );
    scoped
        .commit_application(hidden.sequence, hidden.receipt_digest)
        .await
        .unwrap();
    drop(scoped);
    reopened.close().await.unwrap();
}
