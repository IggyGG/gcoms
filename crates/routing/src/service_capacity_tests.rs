use super::*;
use gcoms_core::TrafficClass;

#[tokio::test]
async fn operator_capacity_bounds_real_streams_and_reserves_interactive_admission() {
    // Exceed the old aggregate ceiling while retaining exact admission bounds.
    // The target is an ordinary TCP listener; every admitted slot owns a socket.
    let listener = tokio::net::TcpListener::bind("127.0.0.62:0").await.unwrap();
    let target = Target::Relay {
        addr: listener.local_addr().unwrap(),
        service_id: [7; 32],
    };
    let service = RelayService::new(
        "127.0.0.61:42000".parse().unwrap(),
        [5; 32],
        [6; 32],
        Arc::new(Directory::new()),
        ServicePolicy {
            max_circuits: 256,
            target_allowed: Arc::new(|a| a.ip().is_loopback()),
            ..Default::default()
        },
    )
    .unwrap();
    let connector = service.gc2_target_connector();
    let mut streams = Vec::new();
    for _ in 0..255 {
        let stream = connector(target.clone(), TrafficClass::Bulk).await.unwrap();
        let accepted = listener.accept().await.unwrap().0;
        streams.push((stream, accepted));
    }
    assert_eq!(service.active_circuits(), 255);
    assert!(connector(target.clone(), TrafficClass::Bulk).await.is_err());
    let interactive = connector(target.clone(), TrafficClass::Interactive)
        .await
        .unwrap();
    let accepted = listener.accept().await.unwrap().0;
    assert_eq!(service.active_circuits(), 256);
    assert!(connector(target.clone(), TrafficClass::Interactive)
        .await
        .is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
    drop((interactive, accepted));
    assert_eq!(service.active_circuits(), 255);
    drop(streams);
    assert_eq!(service.active_circuits(), 0);
    // Failed target authorization must release both class and aggregate slots.
    let denied = Target::Relay {
        addr: "127.0.0.61:42000".parse().unwrap(),
        service_id: [5; 32],
    };
    for _ in 0..300 {
        assert!(connector(denied.clone(), TrafficClass::Bulk).await.is_err());
    }
    assert_eq!(service.active_circuits(), 0);
    let stream = connector(target, TrafficClass::Bulk).await.unwrap();
    drop((stream, listener.accept().await.unwrap()));
    assert_eq!(service.active_circuits(), 0);
}

#[test]
fn service_rejects_aggregate_capacity_above_the_operator_ceiling() {
    for limit in [0, MAX_SERVICE_CIRCUITS + 1, usize::MAX] {
        assert!(RelayService::new(
            "127.0.0.61:42000".parse().unwrap(),
            [5; 32],
            [6; 32],
            Arc::new(Directory::new()),
            ServicePolicy {
                max_circuits: limit,
                ..Default::default()
            }
        )
        .is_err());
    }
    assert_eq!(ServicePolicy::default().max_circuits, 128);
}
