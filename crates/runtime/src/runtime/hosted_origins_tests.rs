use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use gcoms_network::{Founder, NetworkDefaults, SignedNetworkDefaults};

#[tokio::test]
async fn signed_hosted_origins_preserve_catalog_configuration_and_reject_unsigned_hosts() {
    let root = tempfile::tempdir().unwrap();
    crate::private_fs::make_private(root.path(), true).unwrap();
    let signer = gcoms_crypto::IdentityKeypair::generate();
    let now = gcoms_network_client::now_unix();
    let installed = gcoms_network_client::InstalledNetwork {
        trusted_key_b64: URL_SAFE_NO_PAD.encode(signer.public_bytes()),
        signed_defaults: SignedNetworkDefaults::sign(
            NetworkDefaults {
                version: 1,
                network_id: "hosted.test".into(),
                sequence: 1,
                issued_at: now,
                expires_at: now + 3600,
                provider_urls: vec!["https://provider.hosted.test/".into()],
                founders: vec![Founder {
                    name: "r1.relays.hosted.test".into(),
                    service_id: [1; 32],
                    address_hints: vec!["93.184.216.34:4433".parse().unwrap()],
                }],
                dns_domain: "hosted.test".into(),
            },
            &signer,
            vec![],
        )
        .unwrap(),
    };
    let runtime = ProtocolRuntime::open_client_options(
        &root.path().join("profile"),
        "hosted-origin-test-password",
        true,
        crate::RuntimeOptions {
            network: Some(installed),
            carrier: gcoms_sdk::CarrierProfile::Gc2,
            durable_channel_inbox: false,
            listen: "127.0.0.1:0".parse().unwrap(),
            advertise: None,
            relay: None,
            fixture: false,
        },
    )
    .await
    .unwrap();
    let sdk = runtime.sdk_client();
    // No relay bootstrap is installed: an authorized destination must reach
    // route readiness, while an unsigned destination must fail the origin gate.
    let request = |host: &str| gcoms_sdk::CatalogHttpRequest {
        method: "POST".into(),
        url: format!("https://{host}/v1/hosted"),
        body: b"{}".to_vec(),
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        sdk.hosted_channels(gcoms_sdk::hosted_client::Request::Directory {
            endpoint: "https://provider.hosted.test/v1/hosted".into(),
            after: None,
            limit: 1,
        }),
    )
    .await;
    if let Ok(Err(error)) = result {
        assert!(
            !error
                .to_string()
                .contains("catalog origin is not configured"),
            "{error}"
        );
    }
    for explicit in [vec!["catalog.hosted.test".into()], vec![]] {
        sdk.configure_catalog_origins(explicit).await.unwrap();
        let error = sdk
            .catalog_request(request("unsigned.test"))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("catalog origin is not configured"),
            "{error}"
        );
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            sdk.catalog_request(request("provider.hosted.test")),
        )
        .await;
        if let Ok(Err(error)) = result {
            assert!(
                !error
                    .to_string()
                    .contains("catalog origin is not configured"),
                "{error}"
            );
        }
    }
    sdk.configure_catalog_origins(vec!["catalog.hosted.test".into()])
        .await
        .unwrap();
    assert!(sdk
        .configure_catalog_origins(vec!["https://invalid.test".into()])
        .await
        .is_err());
    assert_eq!(
        *runtime.0.catalog_origins.lock().unwrap(),
        vec!["catalog.hosted.test"]
    );
    runtime.shutdown().await.unwrap();
}
