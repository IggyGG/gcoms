#![cfg(feature = "native")]
use gcoms_rpc::*;
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    Arc,
};

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema, ts_rs::TS)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum CounterError {
    TooLarge,
}

#[gcoms_rpc::service(name = "example.counter", version = 1)]
pub trait Counter {
    #[rpc(id = "read", kind = "query")]
    async fn read(&self) -> Result<u32, CounterError>;
    #[rpc(id = "add", kind = "operation")]
    async fn add(&self, context: CallContext, amount: u32) -> Result<u32, CounterError>;
}
struct CounterImpl(Arc<AtomicU32>);
#[async_trait]
impl Counter for CounterImpl {
    async fn read(&self) -> Result<u32, CounterError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
    async fn add(&self, context: CallContext, amount: u32) -> Result<u32, CounterError> {
        assert!(context.operation.is_some());
        if amount > 100 {
            return Err(CounterError::TooLarge);
        }
        Ok(self.0.fetch_add(amount, Ordering::SeqCst) + amount)
    }
}
fn router(
    store: Arc<dyn OperationStore>,
    counter: Arc<AtomicU32>,
    authorized: Arc<AtomicBool>,
) -> Arc<Router> {
    let mut router = Router::new("instance-a", 2, LOCAL_FRAME_LIMIT);
    router
        .register(
            Arc::new(CounterDispatcher(CounterImpl(counter))),
            store,
            Arc::new(move |_: &Caller, _: &str, _: u16, _: &str| authorized.load(Ordering::SeqCst)),
        )
        .unwrap();
    Arc::new(router)
}
fn client(router: Arc<Router>) -> CounterClient<EmbeddedTransport> {
    CounterClient::new(Client::new(
        EmbeddedTransport {
            router,
            caller: Caller {
                principal: "alice".into(),
            },
            destination: "local-test".into(),
        },
        "instance-a",
    ))
}

#[tokio::test]
async fn typed_calls_duplicate_conflicts_recovery_and_revocation() {
    let value = Arc::new(AtomicU32::new(0));
    let allowed = Arc::new(AtomicBool::new(true));
    let store = Arc::new(MemoryStore::default());
    let first = client(router(store.clone(), value.clone(), allowed.clone()));
    assert_eq!(first.read().await.unwrap(), 0);
    let prepared = first.prepare_add(7).unwrap();
    first.inner.start(&prepared).await.unwrap(); // Simulate losing the first reply.
    assert_eq!(
        first
            .inner
            .resume::<u32, CounterError>(&prepared.handle)
            .await
            .unwrap(),
        7
    );
    assert_eq!(first.inner.start_and_wait(&prepared).await.unwrap(), 7);
    assert_eq!(
        first.inner.handles().list().unwrap(),
        vec![prepared.handle.clone()]
    );
    let mut conflicting = first.prepare_add(9).unwrap();
    conflicting.handle = prepared.handle.clone();
    assert_eq!(
        first.inner.start(&conflicting).await.unwrap_err().code,
        ErrorCode::Conflict
    );
    let restarted = client(router(store, value.clone(), allowed.clone()));
    assert_eq!(
        restarted
            .inner
            .resume::<u32, CounterError>(&prepared.handle)
            .await
            .unwrap(),
        7
    );
    assert_eq!(value.load(Ordering::SeqCst), 7);
    allowed.store(false, Ordering::SeqCst);
    assert_eq!(
        restarted
            .inner
            .status(&prepared.handle)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Unauthorized
    );
}

#[tokio::test]
async fn interrupted_admission_is_unknown_and_status_cannot_execute() {
    let value = Arc::new(AtomicU32::new(0));
    let store = Arc::new(MemoryStore::default());
    let c = client(router(
        store.clone(),
        value.clone(),
        Arc::new(AtomicBool::new(true)),
    ));
    let prepared = c.prepare_add(4).unwrap();
    assert_eq!(
        c.inner.status(&prepared.handle).await.unwrap(),
        ReplyBody::Unavailable
    );
    let h = &prepared.handle;
    let key = OperationKey {
        caller: "alice".into(),
        instance: h.instance.clone(),
        service: h.service.clone(),
        version: h.version,
        method: h.method.clone(),
        operation_id: h.operation.id.clone(),
    };
    use sha2::{Digest, Sha256};
    let digest = format!("{:x}", Sha256::digest(br#"{"amount":4}"#));
    store
        .admit(&key, &digest, h.operation.deadline.0, unix_time())
        .await
        .unwrap();
    assert_eq!(c.inner.status(h).await.unwrap(), ReplyBody::OutcomeUnknown);
    assert_eq!(
        c.inner.start(&prepared).await.unwrap(),
        ReplyBody::OutcomeUnknown
    );
    assert_eq!(value.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn journal_bounds_expiry_and_caller_binding() {
    let store = Arc::new(MemoryStore::new(StoreLimits {
        records: 1,
        ..Default::default()
    }));
    let value = Arc::new(AtomicU32::new(0));
    let r = router(store.clone(), value, Arc::new(AtomicBool::new(true)));
    let c = client(r.clone());
    let mut expired = c.prepare_add(1).unwrap();
    expired.handle.operation.deadline = DecimalU64(0);
    assert_eq!(
        c.inner.start(&expired).await.unwrap_err().code,
        ErrorCode::Expired
    );
    let p = c.prepare_add(1).unwrap();
    assert_eq!(c.inner.start_and_wait(&p).await.unwrap(), 1);
    assert_eq!(
        c.inner
            .start(&c.prepare_add(1).unwrap())
            .await
            .unwrap_err()
            .code,
        ErrorCode::Busy
    );
    let stranger = Client::new(
        EmbeddedTransport {
            router: r,
            caller: Caller {
                principal: "mallory".into(),
            },
            destination: "local-test".into(),
        },
        "instance-a",
    );
    assert_eq!(
        stranger.status(&p.handle).await.unwrap(),
        ReplyBody::Unavailable
    );
    let h = &p.handle;
    let key = OperationKey {
        caller: "alice".into(),
        instance: h.instance.clone(),
        service: h.service.clone(),
        version: h.version,
        method: h.method.clone(),
        operation_id: h.operation.id.clone(),
    };
    assert!(store
        .get(&key, unix_time() + DEFAULT_RETENTION_SECS + 1)
        .await
        .unwrap()
        .is_none());
    assert!(matches!(
        c.add(101).await,
        Err(CallError::Rpc(RpcError {
            code: ErrorCode::Busy,
            ..
        }))
    ));
}

#[tokio::test]
async fn request_correlation_and_typed_errors() {
    let c = client(router(
        Arc::new(MemoryStore::default()),
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicBool::new(true)),
    ));
    assert!(matches!(
        c.add(101).await,
        Err(CallError::Service(CounterError::TooLarge))
    ));
    let descriptor = CounterClient::<EmbeddedTransport>::descriptor();
    assert_eq!(descriptor.methods.len(), 2);
    assert_eq!(descriptor.methods[1].kind, MethodKind::Operation);
    let req = Request {
        rpc: WIRE_VERSION,
        id: new_id(),
        instance: "instance-a".into(),
        service: "example.counter".into(),
        version: 1,
        method: "read".into(),
        invocation: Invocation::Call {
            args: serde_json::json!({}),
            operation: None,
        },
    };
    let mut reply = req.reply(ReplyBody::Done {
        outcome: Outcome::Ok(serde_json::json!(0)),
    });
    reply.id = new_id();
    assert!(req.check_reply(&reply).is_err());
}

#[cfg(feature = "file-store")]
#[tokio::test]
async fn encrypted_journal_restart_wrong_key_and_exclusive_lock() {
    let dir = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(dir.path(), true).unwrap();
    let path = dir.path().join("operations");
    let value = Arc::new(AtomicU32::new(0));
    let prepared;
    let previous_owner;
    {
        let store = Arc::new(
            file_store::FileStore::open(&path, [7; 32], "counter", StoreLimits::default()).unwrap(),
        );
        previous_owner = Arc::downgrade(&store);
        assert!(
            file_store::FileStore::open(&path, [7; 32], "counter", StoreLimits::default()).is_err()
        );
        let c = client(router(
            store,
            value.clone(),
            Arc::new(AtomicBool::new(true)),
        ));
        prepared = c.prepare_add(42).unwrap();
        assert_eq!(c.inner.start_and_wait(&prepared).await.unwrap(), 42);
    }
    // Durable completion can be observed before the admitted worker has dropped
    // its router/store references. A restart requires that owner to finish, not
    // merely that the caller has received its terminal result.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while previous_owner.strong_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("previous journal owner released after completion");
    assert!(!std::fs::read(&path)
        .unwrap()
        .windows(7)
        .any(|s| s == b"outcome"));
    assert!(
        file_store::FileStore::open(&path, [8; 32], "counter", StoreLimits::default()).is_err()
    );
    assert!(
        file_store::FileStore::open(&path, [7; 32], "different", StoreLimits::default()).is_err()
    );
    let store = Arc::new(
        file_store::FileStore::open(&path, [7; 32], "counter", StoreLimits::default()).unwrap(),
    );
    let c = client(router(
        store,
        value.clone(),
        Arc::new(AtomicBool::new(true)),
    ));
    assert_eq!(c.inner.start_and_wait(&prepared).await.unwrap(), 42);
    assert_eq!(value.load(Ordering::SeqCst), 42);
}

#[tokio::test]
async fn completion_storage_failure_is_unknown_and_never_reexecuted() {
    struct FailingStore(MemoryStore);
    #[async_trait]
    impl OperationStore for FailingStore {
        async fn admit(
            &self,
            key: &OperationKey,
            digest: &str,
            deadline: u64,
            now: u64,
        ) -> Result<Admission, RpcError> {
            self.0.admit(key, digest, deadline, now).await
        }
        async fn complete(&self, _: &OperationKey, _: ReplyBody) -> Result<(), RpcError> {
            Err(RpcError::new(ErrorCode::Storage, "injected failure"))
        }
        async fn get(
            &self,
            key: &OperationKey,
            now: u64,
        ) -> Result<Option<OperationRecord>, RpcError> {
            self.0.get(key, now).await
        }
    }
    let value = Arc::new(AtomicU32::new(0));
    let c = client(router(
        Arc::new(FailingStore(MemoryStore::default())),
        value.clone(),
        Arc::new(AtomicBool::new(true)),
    ));
    let prepared = c.prepare_add(3).unwrap();
    assert!(matches!(
        c.inner.start_and_wait(&prepared).await,
        Err(CallError::OutcomeUnknown(_))
    ));
    assert_eq!(
        c.inner.start(&prepared).await.unwrap(),
        ReplyBody::OutcomeUnknown
    );
    assert_eq!(value.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn handler_failure_after_effects_remains_unknown_without_reexecution() {
    struct Failing {
        counter: Arc<AtomicU32>,
        panics: bool,
    }
    #[async_trait]
    impl Dispatch for Failing {
        fn descriptor(&self) -> Service {
            CounterContract::descriptor()
        }
        fn validate(
            &self,
            _: &str,
            args: serde_json::Value,
        ) -> Result<serde_json::Value, RpcError> {
            Ok(args)
        }
        async fn invoke(
            &self,
            _: CallContext,
            _: &str,
            _: serde_json::Value,
        ) -> Result<Outcome, RpcError> {
            self.counter.fetch_add(1, Ordering::SeqCst);
            assert!(!self.panics, "injected panic after effects");
            Err(RpcError::protocol("injected serialization failure"))
        }
    }
    for panics in [false, true] {
        let counter = Arc::new(AtomicU32::new(0));
        let mut router = Router::new("instance-a", 1, LOCAL_FRAME_LIMIT);
        router
            .register(
                Arc::new(Failing {
                    counter: counter.clone(),
                    panics,
                }),
                Arc::new(MemoryStore::default()),
                Arc::new(|_: &Caller, _: &str, _: u16, _: &str| true),
            )
            .unwrap();
        let c = client(Arc::new(router));
        let prepared = c.prepare_add(1).unwrap();
        assert!(matches!(
            c.inner.start_and_wait(&prepared).await,
            Err(CallError::OutcomeUnknown(_))
        ));
        assert_eq!(
            c.inner.start(&prepared).await.unwrap(),
            ReplyBody::OutcomeUnknown
        );
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn status_remains_responsive_with_full_workers_and_a_dropped_caller() {
    struct Gated {
        started: Arc<tokio::sync::Notify>,
        finish: Arc<tokio::sync::Notify>,
    }
    #[async_trait]
    impl Counter for Gated {
        async fn read(&self) -> Result<u32, CounterError> {
            Ok(0)
        }
        async fn add(&self, _: CallContext, amount: u32) -> Result<u32, CounterError> {
            self.started.notify_one();
            self.finish.notified().await;
            Ok(amount)
        }
    }
    let started = Arc::new(tokio::sync::Notify::new());
    let finish = Arc::new(tokio::sync::Notify::new());
    let mut router = Router::new("instance-a", 1, LOCAL_FRAME_LIMIT);
    router
        .register(
            Arc::new(CounterDispatcher(Gated {
                started: started.clone(),
                finish: finish.clone(),
            })),
            Arc::new(MemoryStore::default()),
            Arc::new(|_: &Caller, _: &str, _: u16, _: &str| true),
        )
        .unwrap();
    let router = Arc::new(router);
    let c = client(router.clone());
    let prepared = c.prepare_add(8).unwrap();
    assert_eq!(c.inner.start(&prepared).await.unwrap(), ReplyBody::Running);
    started.notified().await;
    assert_eq!(
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            c.inner.status(&prepared.handle)
        )
        .await
        .unwrap()
        .unwrap(),
        ReplyBody::Running
    );
    assert!(matches!(
        c.read().await,
        Err(CallError::Rpc(RpcError {
            code: ErrorCode::Busy,
            ..
        }))
    ));
    assert_eq!(
        c.inner
            .start(&c.prepare_add(1).unwrap())
            .await
            .unwrap_err()
            .code,
        ErrorCode::Busy
    );
    drop(c);
    finish.notify_one();
    assert_eq!(
        client(router)
            .inner
            .resume::<u32, CounterError>(&prepared.handle)
            .await
            .unwrap(),
        8
    );
}

#[tokio::test]
async fn byte_quota_failures_leave_the_original_admission_intact() {
    let store = MemoryStore::new(StoreLimits {
        bytes: 1000,
        ..Default::default()
    });
    let key = OperationKey {
        caller: "alice".into(),
        instance: "instance".into(),
        service: "example".into(),
        version: 1,
        method: "work".into(),
        operation_id: new_id(),
    };
    store
        .admit(&key, "digest", unix_time() + 60, unix_time())
        .await
        .unwrap();
    let result = ReplyBody::Done {
        outcome: Outcome::Ok(serde_json::json!("x".repeat(2000))),
    };
    assert_eq!(
        store.complete(&key, result).await.unwrap_err().code,
        ErrorCode::Busy
    );
    assert!(store
        .get(&key, unix_time())
        .await
        .unwrap()
        .unwrap()
        .result
        .is_none());
    let mut another = key.clone();
    another.operation_id = new_id();
    another.caller = "x".repeat(2000);
    assert!(store
        .admit(&another, "digest", unix_time() + 60, unix_time())
        .await
        .is_err());
    assert!(store.get(&another, unix_time()).await.unwrap().is_none());
}

#[cfg(feature = "file-store")]
#[test]
fn native_handle_storage_survives_reopen_and_simultaneous_views() {
    let dir = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(dir.path(), true).unwrap();
    let path = dir.path().join("handles");
    let one = file_store::FileHandles::open(&path).unwrap();
    let two = file_store::FileHandles::open(&path).unwrap();
    let first = OperationHandle {
        destination: "selected-socket".into(),
        instance: "instance-a".into(),
        service: "example.counter".into(),
        version: 1,
        method: "add".into(),
        operation: OperationToken {
            id: new_id(),
            deadline: DecimalU64(unix_time() + 600),
        },
    };
    let mut second = first.clone();
    second.operation.id = new_id();
    one.retain(&first).unwrap();
    two.retain(&second).unwrap();
    assert_eq!(one.list().unwrap(), vec![first.clone(), second.clone()]);
    assert_eq!(two.list().unwrap(), one.list().unwrap());
    one.forget(&first).unwrap();
    drop(one);
    drop(two);
    assert_eq!(
        file_store::FileHandles::open(&path)
            .unwrap()
            .list()
            .unwrap(),
        vec![second]
    );
    assert!(!String::from_utf8(std::fs::read(path).unwrap())
        .unwrap()
        .contains("args"));
}
