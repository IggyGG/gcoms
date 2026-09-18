use bytes::Bytes;
use gcoms_core::{Cell, CellType};
use gcoms_transport::{
    server::{AcceptedDuplex, Dispatch, ServerLimits, Tp1Server},
    tls::TlsIdentity,
    HopOutcome, TokenRegistry, Tp1Client,
};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{sync::oneshot, time::timeout};

fn echo() -> AcceptedDuplex {
    Box::new(|mut body, mut respond| {
        Box::pin(async move {
            let bytes = gcoms_transport::server::read_body(&mut body, 16 * 1024)
                .await
                .unwrap();
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            send.send_data(bytes, true).unwrap();
        })
    })
}

#[tokio::test]
async fn rejection_precedes_all_handlers_and_does_not_promote_source_admission() {
    let identity = TlsIdentity::generate().unwrap();
    let registry = TokenRegistry::new();
    registry.insert_post("registered-denied");
    registry.insert_post("registered-pass");
    let registered_calls = Arc::new(AtomicUsize::new(0));
    let observed = registered_calls.clone();
    let duplex_calls = Arc::new(AtomicUsize::new(0));
    let observed_duplex = duplex_calls.clone();
    let server = Tp1Server::bind_with_identity(
        "127.0.0.1:0".parse().unwrap(),
        registry,
        Arc::new(move |_, cell| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(Some(cell))
        }),
        Arc::new(|_| None),
        &identity,
    )
    .await
    .unwrap()
    .with_limits(ServerLimits {
        max_connections: 2,
        max_connections_per_ip: 1,
    })
    .with_duplex(Arc::new(move |path| {
        observed_duplex.fetch_add(1, Ordering::SeqCst);
        matches!(path, "legacy-denied" | "legacy-pass").then(echo)
    }))
    .with_dispatch_factory(Arc::new(|| {
        Arc::new(|path, registered| match path {
            "registered-pass" => {
                assert!(registered);
                Dispatch::Pass
            }
            "legacy-pass" => {
                assert!(!registered);
                Dispatch::Pass
            }
            "dispatch-authenticated" => Dispatch::Accepted(echo()),
            _ => Dispatch::Rejected,
        })
    }));
    let address = server.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel();
    let server = tokio::spawn(server.run_until(async {
        let _ = stopped.await;
    }));
    let first = Tp1Client::new().unwrap();
    let cell = Bytes::from(
        Cell::new(CellType::Msg, 0, 0, vec![7; 128])
            .encode_wire()
            .unwrap(),
    );
    for path in ["registered-denied", "legacy-denied", "unknown"] {
        assert_eq!(
            first
                .post_cell_pinned(address, identity.service_id(), path, cell.clone())
                .await
                .unwrap(),
            HopOutcome::Decoy(404)
        );
    }
    assert_eq!(registered_calls.load(Ordering::SeqCst), 0);
    assert_eq!(duplex_calls.load(Ordering::SeqCst), 0);
    // The rejected connection still occupies the one unauthenticated source
    // slot, even though one of its paths exists in the private registry.
    let refused = Tp1Client::new().unwrap();
    assert!(timeout(
        Duration::from_secs(2),
        refused.get_pinned(address, identity.service_id(), "/")
    )
    .await
    .unwrap()
    .is_err());
    assert!(matches!(
        first
            .post_cell_pinned(
                address,
                identity.service_id(),
                "dispatch-authenticated",
                cell.clone()
            )
            .await
            .unwrap(),
        HopOutcome::Accepted(Some(_))
    ));
    let admitted = Tp1Client::new().unwrap();
    assert!(admitted
        .get_pinned(address, identity.service_id(), "/")
        .await
        .is_ok());
    for path in ["registered-pass", "legacy-pass"] {
        assert!(matches!(
            first
                .post_cell_pinned(address, identity.service_id(), path, cell.clone())
                .await
                .unwrap(),
            HopOutcome::Accepted(Some(_))
        ));
    }
    assert_eq!(registered_calls.load(Ordering::SeqCst), 1);
    assert_eq!(duplex_calls.load(Ordering::SeqCst), 1);
    stop.send(()).unwrap();
    timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
