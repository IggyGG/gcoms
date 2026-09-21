#![cfg(all(feature = "embedded", feature = "ipc"))]
use gcoms::{
    async_trait, rpc,
    sdk::{ipc::Capability, ChannelVisibility, GcClient},
    Application, Backend,
};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

#[test]
fn startup_future_keeps_caller_stack_bounded() {
    let opening = Application::builder("stack-fixture").open();
    let bytes = std::mem::size_of_val(&opening);
    assert!(bytes <= 16 * 1024, "startup future occupies {bytes} bytes");
}

#[gcoms::service(name = "example.echo", version = 1)]
trait Echo {
    #[rpc(id = "echo", kind = "query")]
    async fn echo(&self, text: String) -> Result<String, String>;
    #[rpc(id = "count", kind = "operation")]
    async fn count(&self) -> Result<u32, String>;
}
struct Host(Arc<AtomicU32>);
#[async_trait]
impl Echo for Host {
    async fn echo(&self, text: String) -> Result<String, String> {
        Ok(text)
    }
    async fn count(&self) -> Result<u32, String> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst) + 1)
    }
}
fn builder(path: &Path, name: &str, backend: Backend, port: u16) -> gcoms::ApplicationBuilder {
    Application::builder(name)
        .profile(path)
        .unlock_secret("fixture-passphrase")
        .backend(backend)
        .local_fixture()
        .listen(([127, 0, 0, 1], port).into())
}
fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn application_startup_future_fits_nested_client_adapters() {
    // Startup is nested inside consumer/UI futures on default-sized threads.
    // Keep the public future small rather than increasing every caller's stack.
    let startup = Application::builder("stack-budget").open();
    assert!(std::mem::size_of_val(&startup) < 16 * 1024);
}
async fn daemon(
    dir: &Path,
) -> (
    PathBuf,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), String>>,
) {
    let endpoint = dir.join("service.sock");
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let socket = endpoint.clone();
    let task = tokio::spawn(async move {
        gcoms::daemon::serve(&socket, async {
            let _ = stopped.await;
        })
        .await
    });
    for _ in 0..100 {
        if gcoms::control::exchange(&endpoint, gcoms::control::Request::Ping)
            .await
            .is_ok()
        {
            return (endpoint, stop, task);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("daemon startup timed out")
}
async fn qualify(backend: Backend, dir: &Path) {
    let (a_path, b_path) = (dir.join("alice.profile"), dir.join("bob.profile"));
    let (a_port, b_port) = (port(), port());
    let client_app = builder(&a_path, "alice", backend.clone(), a_port)
        .rpc_contract(EchoContract::descriptor())
        .open()
        .await
        .unwrap();
    let alice = client_app.peer().await.unwrap();
    let counter = Arc::new(AtomicU32::new(0));
    let allowed = alice.principal();
    let server_builder = || {
        builder(&b_path, "bob", backend.clone(), b_port)
            .peer(alice.clone())
            .service(
                Arc::new(EchoDispatcher(Host(counter.clone()))),
                Arc::new({
                    let allowed = allowed.clone();
                    move |caller: &rpc::Caller, _: &str, _: u16, _: &str| {
                        caller.principal == allowed
                    }
                }),
            )
    };
    let server = server_builder().open().await.unwrap();
    let bob = server.peer().await.unwrap();
    assert_ne!(alice.identity, bob.identity);
    client_app.trust_peer(bob.clone()).await.unwrap();
    let client = EchoClient::new(
        client_app
            .rpc(&bob, "bob", &EchoContract::descriptor())
            .unwrap(),
    );
    let reply = tokio::time::timeout(Duration::from_secs(10), client.echo("hello".into())).await;
    assert!(
        reply.is_ok(),
        "RPC workers: client={:?}, server={:?}; inbox counts: client={}, server={}",
        client_app.worker_error(),
        server.worker_error(),
        client_app
            .messaging()
            .application_inbox(0, 32)
            .await
            .unwrap()
            .len(),
        server
            .messaging()
            .application_inbox(0, 32)
            .await
            .unwrap()
            .len()
    );
    assert_eq!(reply.unwrap().unwrap(), "hello");
    let prepared = client.prepare_count().unwrap();
    assert_eq!(client.inner.start_and_wait(&prepared).await.unwrap(), 1);
    // Mixed inbox: ordinary messages still arrive while the same consumer handles RPC.
    client_app
        .messaging()
        .submit_durable_opaque(&bob.contact, "example.message", b"durable hello")
        .await
        .unwrap();
    let delivery = tokio::time::timeout(Duration::from_secs(10), server.receive())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delivery.message.body, b"durable hello");
    drop(delivery);
    let delivery = tokio::time::timeout(Duration::from_secs(10), server.receive())
        .await
        .unwrap()
        .unwrap();
    delivery.acknowledge().await.unwrap();
    // Journal replay after a real runtime restart cannot repeat the effect.
    server.stop_profile().await.unwrap();
    let server = server_builder().open().await.unwrap();
    let renewed = server.peer().await.unwrap();
    assert_eq!(bob.identity, renewed.identity);
    client_app.trust_peer(renewed).await.unwrap();
    // Route recovery can outlast the RPC deadline. Resume the original handle;
    // a timeout must never cause this test to submit a new operation identity.
    let replay = match client.inner.start_and_wait(&prepared).await {
        Err(rpc::CallError::Rpc(error)) if error.code == rpc::ErrorCode::Timeout => {
            client.inner.resume::<u32, String>(&prepared.handle).await
        }
        outcome => outcome,
    };
    assert_eq!(replay.unwrap(), 1);
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    // Channel invitation is available through both backends.
    server
        .messaging()
        .create_channel("invite-test", "bob", 16, ChannelVisibility::Private)
        .await
        .unwrap();
    let invitation = server
        .messaging()
        .create_channel_invitation("invite-test", 300)
        .await
        .unwrap();
    let inspected = client_app
        .messaging()
        .inspect_channel_invitation(&invitation.link)
        .await
        .unwrap();
    assert_eq!(inspected.channel, "invite-test");
    assert_eq!(
        client_app
            .messaging()
            .join_channel_invitation(&invitation.link, "alice", 10)
            .await
            .unwrap(),
        "invite-test"
    );
    assert!(builder(&a_path, "different-app", backend.clone(), a_port)
        .receive_messages(false)
        .open()
        .await
        .is_err());
    client_app.stop_profile().await.unwrap();
    server.stop_profile().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn embedded_typed_rpc_messages_invites_and_restart() {
    let dir = private_dir();
    qualify(Backend::Embedded, dir.path()).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_typed_rpc_messages_invites_and_restart() {
    let dir = private_dir();
    let (endpoint, stop, task) = daemon(dir.path()).await;
    qualify(Backend::Attach { endpoint }, dir.path()).await;
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_attachment_credentials_exclusive_inbox_and_detach() {
    let dir = private_dir();
    let (endpoint, stop, task) = daemon(dir.path()).await;
    let backend = Backend::Attach { endpoint };
    let path = dir.path().join("profile");
    let bind_port = port();
    let app = builder(&path, "app", backend.clone(), bind_port)
        .open()
        .await
        .unwrap();
    let identity = app.identity();
    assert!(builder(&path, "app", backend.clone(), bind_port)
        .open()
        .await
        .is_err());
    assert!(builder(&path, "app", backend.clone(), bind_port)
        .unlock_secret("wrong")
        .receive_messages(false)
        .open()
        .await
        .is_err());
    let observer = builder(&path, "app", backend.clone(), bind_port)
        .receive_messages(false)
        .open()
        .await
        .unwrap();
    assert_eq!(identity.safety_number, observer.identity().safety_number);
    app.close().await.unwrap();
    // Detaching releases only the consumer, retaining the hosted runtime.
    let app = builder(&path, "app", backend, bind_port)
        .open()
        .await
        .unwrap();
    assert_eq!(identity.safety_number, app.identity().safety_number);
    observer.close().await.unwrap();
    app.stop_profile().await.unwrap();
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn profile_credentials_capabilities_and_lease_release() {
    let dir = private_dir();
    let (endpoint, stop, task) = daemon(dir.path()).await;
    let path = dir.path().join("secured");
    let listen_port = port();
    let app = builder(
        &path,
        "secured",
        Backend::Attach {
            endpoint: endpoint.clone(),
        },
        listen_port,
    )
    .receive_messages(false)
    .open()
    .await
    .unwrap();
    let registration: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dir.path().join("secured.gcoms-registration")).unwrap(),
    )
    .unwrap();
    let token: [u8; 32] = serde_json::from_value(registration["token"].clone()).unwrap();
    let attachment = gcoms::control::exchange(
        &endpoint,
        gcoms::control::Request::Open {
            config: gcoms::control::ProfileConfig {
                application: "secured".into(),
                profile: path,
                listen: ([127, 0, 0, 1], listen_port).into(),
                fixture: true,
                carrier: Default::default(),
                advertise: None,
                relay: None,
                network: None,
                network_recovery: true,
                providers: Vec::new(),
            },
            token,
            secret: "fixture-passphrase".into(),
            create: false,
        },
    )
    .await
    .unwrap()
    .unwrap();
    use gcoms::sdk::IpcClient;
    assert!(IpcClient::connect(
        &attachment.endpoint,
        "unauthenticated",
        vec![Capability::IdentityRead]
    )
    .await
    .is_err());
    assert!(IpcClient::connect_profile(
        &attachment.endpoint,
        "wrong-token",
        vec![Capability::IdentityRead],
        [0; 32]
    )
    .await
    .is_err());
    let observer = IpcClient::connect_profile(
        &attachment.endpoint,
        "observer",
        vec![Capability::IdentityRead],
        token,
    )
    .await
    .unwrap();
    assert!(observer.application_inbox(0, 1).await.is_err());
    assert!(observer.import_network_invitation("denied").await.is_err());
    // A denied reader never acquires the exclusive consumer lease.
    let first = IpcClient::connect_profile(
        &attachment.endpoint,
        "first",
        vec![Capability::IdentityRead, Capability::DurableApplication],
        token,
    )
    .await
    .unwrap();
    first.application_inbox(0, 1).await.unwrap();
    let next = IpcClient::connect_profile(
        &attachment.endpoint,
        "next",
        vec![Capability::IdentityRead, Capability::DurableApplication],
        token,
    )
    .await
    .unwrap();
    assert!(next.application_inbox(0, 1).await.is_err());
    assert!(next.commit_application(0, [0; 32]).await.is_err());
    first.close().await;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if next.application_inbox(0, 1).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    next.close().await;
    observer.close().await;
    app.stop_profile().await.unwrap();
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bundled_daemon_starts_once_and_attaches() {
    struct Stop(u32);
    impl Drop for Stop {
        fn drop(&mut self) {
            #[cfg(unix)]
            let _ = rustix::process::kill_process(
                rustix::process::Pid::from_raw(self.0 as i32).unwrap(),
                rustix::process::Signal::TERM,
            );
            #[cfg(windows)]
            {
                use windows_sys::Win32::{
                    Foundation::CloseHandle,
                    System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE},
                };
                // SAFETY: the kernel supplied this PID for our private test pipe.
                // Both profiles are saved and stopped before normal cleanup.
                unsafe {
                    let process = OpenProcess(PROCESS_TERMINATE, 0, self.0);
                    if !process.is_null() {
                        TerminateProcess(process, 0);
                        CloseHandle(process);
                    }
                }
            }
        }
    }
    let dir = private_dir();
    let endpoint = dir.path().join("bundle.sock");
    let backend = Backend::Shared {
        // Cross-built test paths are rooted without a Windows drive prefix.
        executable: PathBuf::from(env!("CARGO_BIN_EXE_gcomsd"))
            .canonicalize()
            .unwrap(),
        endpoint: endpoint.clone(),
    };
    let first = builder(&dir.path().join("first"), "first", backend.clone(), port())
        .open()
        .await
        .unwrap();
    let socket = gcoms::sdk::local::connect(&gcoms::sdk::LocalEndpoint::new(&endpoint))
        .await
        .unwrap();
    let pid = daemon_pid(&socket);
    let guard = Stop(pid);
    drop(socket);
    let second = builder(&dir.path().join("second"), "second", backend, port())
        .open()
        .await
        .unwrap();
    let socket = gcoms::sdk::local::connect(&gcoms::sdk::LocalEndpoint::new(&endpoint))
        .await
        .unwrap();
    assert_eq!(pid, daemon_pid(&socket));
    drop(socket);
    assert_ne!(
        first.identity().safety_number,
        second.identity().safety_number
    );
    first.stop_profile().await.unwrap();
    second.stop_profile().await.unwrap();
    drop(guard);
    tokio::time::timeout(Duration::from_secs(5), async {
        while gcoms::sdk::local::connect(&gcoms::sdk::LocalEndpoint::new(&endpoint))
            .await
            .is_ok()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

fn daemon_pid(socket: &gcoms::sdk::local::ClientStream) -> u32 {
    #[cfg(unix)]
    {
        socket.peer_cred().unwrap().pid().unwrap() as u32
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        let mut pid = 0;
        // SAFETY: the live named-pipe client owns the handle, and pid is writable.
        assert_ne!(
            unsafe {
                windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId(
                    socket.as_raw_handle(),
                    &mut pid,
                )
            },
            0,
            "{}",
            std::io::Error::last_os_error()
        );
        pid
    }
}

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    gcoms::runtime::private_fs::make_private(dir.path(), true).unwrap();
    dir
}

#[cfg(feature = "files")]
async fn qualify_files(backend: Backend, dir: &Path) {
    use gcoms::sdk::sharing::{Request, Scope, Status};
    let path = dir.join("files.profile");
    let listen_port = port();
    let app = builder(&path, "files", backend.clone(), listen_port)
        .receive_messages(false)
        .open()
        .await
        .unwrap();
    if let Backend::Attach { endpoint } = &backend {
        let unauthorized = dir.join("unopened-cache");
        assert!(gcoms::control::exchange(
            endpoint,
            gcoms::control::Request::ConfigureFileCache {
                profile: path.clone(),
                token: [0; 32],
                path: unauthorized.clone(),
                key: [0; 32],
                config: Default::default(),
            }
        )
        .await
        .err()
        .unwrap()
        .contains("credential rejected"));
        assert!(!unauthorized.exists());
    }
    let channel = app
        .messaging()
        .create_channel("files", "owner", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    let source = vec![0x71; 256 * 1024 + 17];
    let id = app
        .files()
        .import(
            Scope {
                channel: channel.0,
                participants: vec![],
            },
            "stream.bin".into(),
            source.len() as u64,
            &mut source.as_slice(),
        )
        .await
        .unwrap();
    assert_eq!(
        app.files().list().await.unwrap().files[0].status,
        Status::Complete
    );
    assert!(app
        .files()
        .request(Request::WritePiece {
            id,
            piece: 0,
            bytes: vec![0; 256 * 1024 + 1]
        })
        .await
        .is_err());
    assert!(app
        .files()
        .prepare(
            Scope {
                channel: [0; 32],
                participants: vec![]
            },
            "forbidden.bin".into(),
            10
        )
        .await
        .is_err());
    let output = dir.join("export.bin");
    app.files().save_path(id, &output).await.unwrap();
    assert_eq!(std::fs::read(&output).unwrap(), source);
    assert!(
        app.files().save_path(id, &output).await.is_err(),
        "cannot overwrite a local destination"
    );
    app.files()
        .request(Request::Configure(gcoms::sdk::sharing::CacheConfig {
            quota_bytes: 2 * 1024 * 1024,
            retention_secs: 86400,
        }))
        .await
        .unwrap();
    let identity = app.identity().safety_number;
    app.stop_profile().await.unwrap();
    let app = builder(&path, "files", backend, listen_port)
        .receive_messages(false)
        .open()
        .await
        .unwrap();
    assert_eq!(app.identity().safety_number, identity);
    assert_eq!(
        app.files().list().await.unwrap().config.quota_bytes,
        2 * 1024 * 1024
    );
    let mut reopened = Vec::new();
    app.files().export(id, &mut reopened).await.unwrap();
    assert_eq!(reopened, source);
    app.files().cancel(id).await.unwrap();
    assert!(app.files().read_piece(id, 0).await.is_err());
    app.stop_profile().await.unwrap();
}
#[cfg(feature = "files")]
#[tokio::test]
async fn file_streaming_reopen_and_bounds_embedded() {
    let dir = tempfile::tempdir().unwrap();
    gcoms::runtime::private_fs::make_private(dir.path(), true).unwrap();
    qualify_files(Backend::Embedded, dir.path()).await;
}
#[cfg(feature = "files")]
#[tokio::test]
async fn file_streaming_reopen_and_bounds_ipc() {
    let dir = tempfile::tempdir().unwrap();
    gcoms::runtime::private_fs::make_private(dir.path(), true).unwrap();
    let (endpoint, stop, task) = daemon(dir.path()).await;
    qualify_files(Backend::Attach { endpoint }, dir.path()).await;
    let _ = stop.send(());
    task.await.unwrap().unwrap();
}

#[cfg(feature = "files")]
#[tokio::test]
async fn files_cross_embedded_and_ipc_with_pause_resume_and_current_membership() {
    use gcoms::sdk::sharing::{Scope, Status};
    let dir = tempfile::tempdir().unwrap();
    gcoms::runtime::private_fs::make_private(dir.path(), true).unwrap();
    let (endpoint, stop, task) = daemon(dir.path()).await;
    let source = builder(
        &dir.path().join("source"),
        "source",
        Backend::Embedded,
        port(),
    )
    .receive_messages(false)
    .open()
    .await
    .unwrap();
    let receiver = builder(
        &dir.path().join("receiver"),
        "receiver",
        Backend::Attach { endpoint },
        port(),
    )
    .receive_messages(false)
    .open()
    .await
    .unwrap();
    let channel = source
        .messaging()
        .create_channel("shared", "owner", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    let pending = receiver
        .messaging()
        .prepare_channel_join("receiver")
        .await
        .unwrap();
    let package = receiver
        .messaging()
        .channel_key_package(pending)
        .await
        .unwrap();
    let welcome = source
        .messaging()
        .admit_channel("shared", &package, "receiver")
        .await
        .unwrap();
    receiver
        .messaging()
        .join_channel(pending, "shared", ChannelVisibility::Private, &welcome)
        .await
        .unwrap();
    receiver.files().list().await.unwrap();
    let content = vec![0x35; 256 * 1024 + 13];
    let id = source
        .files()
        .import(
            Scope {
                channel: channel.0,
                participants: vec![],
            },
            "shared.bin".into(),
            content.len() as u64,
            &mut content.as_slice(),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        while !receiver
            .files()
            .list()
            .await
            .unwrap()
            .files
            .iter()
            .any(|f| f.id == id)
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    receiver.files().accept(id).await.unwrap();
    receiver.files().pause(id).await.unwrap();
    assert_eq!(
        receiver.files().list().await.unwrap().files[0].status,
        Status::Paused
    );
    receiver.files().resume(id).await.unwrap();
    tokio::time::timeout(Duration::from_secs(25), async {
        while receiver.files().list().await.unwrap().files[0].status != Status::Complete {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("mixed backend transfer completes");
    let mut exported = Vec::new();
    receiver.files().export(id, &mut exported).await.unwrap();
    assert_eq!(exported, content);
    let member = receiver
        .messaging()
        .channel_roster("shared")
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.is_self)
        .unwrap()
        .member_id;
    source
        .messaging()
        .remove_channel_member("shared", member)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if receiver
                .messaging()
                .list_channels()
                .await
                .unwrap()
                .iter()
                .all(|c| c.status != gcoms::sdk::ChannelStatus::Active)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(receiver
        .files()
        .prepare(
            Scope {
                channel: channel.0,
                participants: vec![]
            },
            "forbidden.bin".into(),
            1
        )
        .await
        .is_err());
    source.stop_profile().await.unwrap();
    receiver.stop_profile().await.unwrap();
    let _ = stop.send(());
    task.await.unwrap().unwrap();
}

#[cfg(feature = "files")]
#[tokio::test]
async fn legacy_cache_reconnect_revalidates_journals_in_both_backends() {
    use gcoms::sdk::sharing::{Request, Scope};
    let dir = private_dir();
    let (endpoint, stop, task) = daemon(dir.path()).await;
    for (index, backend) in [Backend::Embedded, Backend::Attach { endpoint }]
        .into_iter()
        .enumerate()
    {
        let app = builder(
            &dir.path().join(format!("profile-{index}")),
            "cache",
            backend,
            port(),
        )
        .receive_messages(false)
        .open()
        .await
        .unwrap();
        let cache = dir.path().join(format!("legacy-{index}.pieces"));
        let key = [0x54; 32];
        app.configure_file_cache(&cache, key, Default::default())
            .await
            .unwrap();
        let channel = app
            .messaging()
            .create_channel("cache", "owner", 8, ChannelVisibility::Private)
            .await
            .unwrap();
        let id = app
            .files()
            .import(
                Scope {
                    channel: channel.0,
                    participants: vec![],
                },
                "retained.bin".into(),
                1,
                &mut b"x".as_slice(),
            )
            .await
            .unwrap();
        let name: String = id.iter().map(|byte| format!("{byte:02x}")).collect();
        let journal = cache.join(name).join("state");
        app.files()
            .request(Request::SetEnabled(false))
            .await
            .unwrap();
        let original = std::fs::read(&journal).unwrap();
        let mut damaged = original.clone();
        damaged[0] ^= 1;
        std::fs::write(&journal, damaged).unwrap();
        assert!(app
            .configure_file_cache(&cache, key, Default::default())
            .await
            .is_err());
        assert!(
            app.files().list().await.is_err(),
            "a failed reopen must not select another cache"
        );
        std::fs::write(&journal, original).unwrap();
        app.configure_file_cache(&cache, key, Default::default())
            .await
            .unwrap();
        assert_eq!(app.files().read_piece(id, 0).await.unwrap(), b"x");
        app.stop_profile().await.unwrap();
    }
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}
