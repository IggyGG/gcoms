use super::*;
use std::time::Duration;
use tokio::net::TcpListener;

struct RetainedDirectory(Mutex<Vec<u8>>);

impl RoutingStateStore for RetainedDirectory {
    fn load(&self) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, String> {
        Ok(Some(zeroize::Zeroizing::new(
            self.0.lock().unwrap().clone(),
        )))
    }

    fn save(&self, bytes: &[u8]) -> Result<(), String> {
        *self.0.lock().unwrap() = bytes.to_vec();
        Ok(())
    }
}

#[tokio::test]
async fn gc2_catalog_never_dials_retained_legacy_entries() {
    for current in [true, false] {
        let first = TcpListener::bind("127.0.0.81:0").await.unwrap();
        let second = TcpListener::bind("127.0.0.82:0").await.unwrap();
        let legacy = gcoms_routing::Directory::new();
        for (index, listener) in [&first, &second].into_iter().enumerate() {
            legacy
                .install(
                    gcoms_routing::directory::Relay {
                        addr: listener.local_addr().unwrap(),
                        service_id: [index as u8 + 1; 32],
                        reentry_cap: [31; 32],
                        circuit_cap: [32; 32],
                        expires_at: now_unix() + 3600,
                    },
                    now_unix(),
                )
                .unwrap();
        }
        let retained = Arc::new(RetainedDirectory(Mutex::new(
            legacy.encode_private().unwrap(),
        )));
        let node = start_with_routing(
            NodeConfig {
                seed: [83; 32],
                listen: "127.0.0.83:0".parse().unwrap(),
                control: None,
                advertise: None,
                inbox_relay: None,
                profile: if current {
                    NodeProfile::gchat_file_transfer_fixture(2, 83)
                } else {
                    NodeProfile::fixture()
                },
                alias_lifecycle: Default::default(),
            },
            RoutingConfig {
                routing_state: Some(retained),
                catalog_origins: vec!["catalog.test".into()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(node.uses_gc2_routing(), current);
        assert_eq!(
            node.routing
                .as_ref()
                .unwrap()
                .discovery
                .directory
                .introductions()
                .len(),
            2
        );
        let request = node.catalog_request("GET", "https://catalog.test/v1/catalog", &[]);
        if current {
            let error = tokio::time::timeout(Duration::from_millis(500), request)
                .await
                .expect("missing current entries must fail without a legacy connection")
                .unwrap_err();
            assert_eq!(error, "no ready independent GC/2 route");
            for listener in [&first, &second] {
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), listener.accept())
                        .await
                        .is_err(),
                    "retained legacy entries must not receive a current catalog request"
                );
            }
        } else {
            // Positive control: the same retained directory remains usable by
            // an explicitly legacy profile. Stop before the TLS handshake.
            tokio::time::timeout(Duration::from_secs(2), async {
                tokio::select! {
                    result = request => panic!("legacy catalog did not attempt its route: {result:?}"),
                    result = first.accept() => { result.unwrap(); },
                    result = second.accept() => { result.unwrap(); },
                }
            }).await.expect("legacy catalog must still use its retained route");
        }
        node.shutdown().await;
    }
}
