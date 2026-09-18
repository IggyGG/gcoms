use bytes::Bytes;
use gcoms_core::{Cell, CellType, TrafficClass};
use gcoms_transport::{
    connector::{ConnectFuture, Connector, DirectConnector},
    server::Tp1Server,
    tls::TlsIdentity,
    TokenRegistry, Tp1Client,
};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

type Observed = Arc<Mutex<Vec<(Option<TrafficClass>, Vec<(SocketAddr, [u8; 32])>)>>>;

struct ObservingConnector {
    bind: bool,
    observed: Observed,
}

impl Connector for ObservingConnector {
    fn connect(&self, addr: SocketAddr, service_id: [u8; 32]) -> ConnectFuture<'_> {
        DirectConnector.connect(addr, service_id)
    }
    fn binds_traffic_class(&self) -> bool {
        self.bind
    }
    fn connect_excluding<'a>(
        &'a self,
        addr: SocketAddr,
        service_id: [u8; 32],
        excluded: &'a [(SocketAddr, [u8; 32])],
    ) -> ConnectFuture<'a> {
        self.observed
            .lock()
            .unwrap()
            .push((None, excluded.to_vec()));
        DirectConnector.connect(addr, service_id)
    }
    fn connect_with_class_excluding<'a>(
        &'a self,
        addr: SocketAddr,
        service_id: [u8; 32],
        excluded: &'a [(SocketAddr, [u8; 32])],
        class: TrafficClass,
    ) -> ConnectFuture<'a> {
        self.observed
            .lock()
            .unwrap()
            .push((Some(class), excluded.to_vec()));
        DirectConnector.connect(addr, service_id)
    }
}

#[tokio::test]
async fn class_bound_pool_partitions_dials_and_warming_but_legacy_pool_stays_shared() {
    for bound in [false, true] {
        let identity = TlsIdentity::generate().unwrap();
        let registry = TokenRegistry::new();
        registry.insert_post("echo");
        let server = Tp1Server::bind_with_identity(
            "127.0.0.1:0".parse().unwrap(),
            registry,
            Arc::new(|_, cell| Ok(Some(cell))),
            Arc::new(|_| None),
            &identity,
        )
        .await
        .unwrap();
        let address = server.local_addr().unwrap();
        let pin = identity.service_id();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(server.run_until(async {
            let _ = stopped.await;
        }));
        let observed = Arc::new(Mutex::new(Vec::new()));
        let client = Arc::new(
            Tp1Client::with_connector(Arc::new(ObservingConnector {
                bind: bound,
                observed: observed.clone(),
            }))
            .unwrap(),
        );
        let exclusions = [
            ("192.0.2.1:443".parse().unwrap(), [1; 32]),
            ("192.0.2.2:443".parse().unwrap(), [2; 32]),
        ];
        client
            .warm_excluding_with_class(address, pin, &exclusions, TrafficClass::Bulk)
            .await
            .unwrap();
        let reversed = [exclusions[1], exclusions[0]];
        client
            .warm_excluding_with_class(address, pin, &reversed, TrafficClass::Bulk)
            .await
            .unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..8 {
            let client = client.clone();
            tasks.spawn(async move {
                let class = if index % 2 == 0 {
                    TrafficClass::Interactive
                } else {
                    TrafficClass::Bulk
                };
                let cell = Cell::new(CellType::Msg, 0, 0, vec![index; 128]);
                let response = client
                    .post_cell_with_class(
                        address,
                        pin,
                        "echo",
                        Bytes::from(cell.encode_wire().unwrap()),
                        &exclusions,
                        class,
                    )
                    .await
                    .unwrap();
                let gcoms_transport::HopOutcome::Accepted(Some(echo)) = response else {
                    panic!("echo required");
                };
                assert_eq!(echo.payload, cell.payload);
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        let calls = observed.lock().unwrap().clone();
        assert_eq!(calls.len(), if bound { 2 } else { 1 });
        assert_eq!(
            calls[0],
            (bound.then_some(TrafficClass::Bulk), exclusions.to_vec())
        );
        if bound {
            assert_eq!(
                calls[1],
                (Some(TrafficClass::Interactive), exclusions.to_vec())
            );
        }
        assert_eq!(client.pooled_connections().await, calls.len());
        // A different exclusion set cannot reuse either class's earlier route.
        client
            .warm_excluding_with_class(address, pin, &[], TrafficClass::Bulk)
            .await
            .unwrap();
        assert_eq!(observed.lock().unwrap().len(), calls.len() + 1);
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
    }
}

struct IncompleteClassConnector;
impl Connector for IncompleteClassConnector {
    fn binds_traffic_class(&self) -> bool {
        true
    }
    fn connect(&self, _addr: SocketAddr, _service_id: [u8; 32]) -> ConnectFuture<'_> {
        panic!("declared class binding must never fall back to legacy connect")
    }
}

#[tokio::test]
async fn declaring_class_binding_without_implementing_it_fails_closed() {
    let client = Tp1Client::with_connector(Arc::new(IncompleteClassConnector)).unwrap();
    let error = client
        .warm_excluding_with_class(
            "192.0.2.3:443".parse().unwrap(),
            [3; 32],
            &[],
            TrafficClass::Bulk,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("explicit class routing"));
}

#[tokio::test]
async fn body_and_prepared_subscriptions_use_their_selected_class_pool() {
    let identity = TlsIdentity::generate().unwrap();
    let registry = TokenRegistry::new();
    registry.insert_stream("stream");
    let workers = Arc::new(Mutex::new(Vec::new()));
    let owned = workers.clone();
    let on_stream: gcoms_transport::server::StreamHandler = Arc::new(move |_| {
        let owned = owned.clone();
        Some(Box::new(move |sink: gcoms_transport::server::StreamSink| {
            owned.lock().unwrap().push(tokio::spawn(async move {
                assert!(
                    sink.send(Cell::new(CellType::Msg, 0, 0, vec![9; 128]))
                        .await
                );
            }));
        }) as gcoms_transport::server::AcceptedStream)
    });
    let server = Tp1Server::bind_with_identity(
        "127.0.0.1:0".parse().unwrap(),
        registry,
        Arc::new(|_, _| Ok(None)),
        on_stream,
        &identity,
    )
    .await
    .unwrap();
    let address = server.local_addr().unwrap();
    let pin = identity.service_id();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(server.run_until(async {
        let _ = stopped.await;
    }));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let client = Tp1Client::with_connector(Arc::new(ObservingConnector {
        bind: true,
        observed: observed.clone(),
    }))
    .unwrap();
    let mut body = client
        .open_stream_body_with_class(address, pin, "stream", None, TrafficClass::Bulk)
        .await
        .unwrap();
    assert_eq!(body.recv().await.unwrap().unwrap().payload, vec![9; 128]);
    drop(body);
    let mut prepared = client
        .open_stream_prepared_with_class(address, pin, "stream", TrafficClass::Bulk, || {
            Ok(Bytes::new())
        })
        .await
        .unwrap();
    assert_eq!(
        prepared.recv().await.unwrap().unwrap().payload,
        vec![9; 128]
    );
    drop(prepared);
    let mut interactive = client
        .open_stream_body_pinned(address, pin, "stream", None)
        .await
        .unwrap();
    assert_eq!(
        interactive.recv().await.unwrap().unwrap().payload,
        vec![9; 128]
    );
    drop(interactive);
    assert_eq!(
        *observed.lock().unwrap(),
        vec![
            (Some(TrafficClass::Bulk), Vec::new()),
            (Some(TrafficClass::Interactive), Vec::new())
        ]
    );
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
    let handles = std::mem::take(&mut *workers.lock().unwrap());
    for worker in handles {
        worker.await.unwrap();
    }
}
