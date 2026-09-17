#![cfg(all(feature = "native", not(target_arch = "wasm32")))]
use gcoms_rpc::{
    gc::{DirectLink, GcEndpoint, Peer},
    *,
};
use gcoms_sdk::{EmbeddedClient, GcClient};
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc, Mutex,
};

#[gcoms_rpc::service(name = "example.echo", version = 1)]
trait Echo {
    #[rpc(id = "echo", kind = "query")]
    async fn echo(&self, value: String) -> Result<String, String>;
    #[rpc(id = "count", kind = "operation")]
    async fn count(&self) -> Result<u32, String>;
}
struct EchoImpl(Arc<AtomicU32>);
#[async_trait]
impl Echo for EchoImpl {
    async fn echo(&self, value: String) -> Result<String, String> {
        Ok(value)
    }
    async fn count(&self) -> Result<u32, String> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst) + 1)
    }
}
async fn peer(seed: u8) -> EmbeddedClient {
    let saved = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let node = gcoms_node::node::start_persistent(
        gcoms_node::node::NodeConfig {
            seed: [seed; 32],
            listen: "127.0.0.1:0".parse().unwrap(),
            control: None,
            advertise: None,
            inbox_relay: None,
            profile: gcoms_node::node::NodeProfile::fixture(),
            alias_lifecycle: Default::default(),
        },
        Arc::new(move |bytes| {
            saved.lock().unwrap().push(bytes);
            Ok(())
        }),
    )
    .await
    .unwrap();
    node.enable_durable_applications().await.unwrap();
    EmbeddedClient::new(node)
}
fn binding(client: &EmbeddedClient) -> Peer {
    Peer {
        identity: client.node().info.identity_pk.clone(),
        contact: client.identity().contact_card,
        component: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_persistent_gc_peers_roundtrip_and_recover_without_reexecution() {
    let a = peer(0xd1).await;
    let b = peer(0xd2).await;
    let count = Arc::new(AtomicU32::new(0));
    let mut router = Router::new("echo-instance", 4, 11_000);
    let alice = binding(&a);
    let bob = binding(&b);
    let allowed = alice.principal();
    router
        .register(
            Arc::new(EchoDispatcher(EchoImpl(count.clone()))),
            Arc::new(MemoryStore::default()),
            Arc::new(move |caller: &Caller, _: &str, _: u16, _: &str| caller.principal == allowed),
        )
        .unwrap();
    let services = vec![("example.echo".into(), 1)];
    let client_endpoint = GcEndpoint::new(
        Arc::new(DirectLink(Arc::new(a.clone()))),
        vec![bob.clone()],
        &services,
        None,
    )
    .await
    .unwrap();
    let server_endpoint = GcEndpoint::new(
        Arc::new(DirectLink(Arc::new(b.clone()))),
        vec![alice],
        &services,
        Some(Arc::new(router)),
    )
    .await
    .unwrap();
    let (a_stop, a_stopped) = tokio::sync::oneshot::channel::<()>();
    let (b_stop, b_stopped) = tokio::sync::oneshot::channel::<()>();
    let endpoint = client_endpoint.clone();
    let a_task = tokio::spawn(async move {
        endpoint
            .run(async {
                let _ = a_stopped.await;
            })
            .await
    });
    let endpoint = server_endpoint.clone();
    let b_task = tokio::spawn(async move {
        endpoint
            .run(async {
                let _ = b_stopped.await;
            })
            .await
    });
    let transport = client_endpoint.transport(&bob, "example.echo", 1).unwrap();
    let client = EchoClient::new(Client::new(transport, "echo-instance"));
    assert_eq!(client.echo("Hello GC".into()).await.unwrap(), "Hello GC");
    assert!(matches!(
        client.echo("x".repeat(16_000)).await,
        Err(CallError::Rpc(RpcError {
            code: ErrorCode::PayloadTooLarge,
            ..
        }))
    ));
    let prepared = client.prepare_count().unwrap();
    client.inner.start(&prepared).await.unwrap();
    assert_eq!(
        client
            .inner
            .resume::<u32, String>(&prepared.handle)
            .await
            .unwrap(),
        1
    );
    assert_eq!(client.inner.start_and_wait(&prepared).await.unwrap(), 1);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    a_stop.send(()).unwrap();
    b_stop.send(()).unwrap();
    a_task.await.unwrap().unwrap();
    b_task.await.unwrap().unwrap();
    a.node().shutdown().await;
    b.node().shutdown().await;
}
