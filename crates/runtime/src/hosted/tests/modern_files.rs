use super::*;
use crate::modern_files::ModernFileService;
use gcoms_sdk::*;
use gcoms_sdk::{sharing::Status, sharing_v2 as files};
use std::time::Duration;
use tokio::sync::Mutex;

struct FileClient {
    client: Mutex<Client>,
    tamper: AtomicBool,
    contact_gate: Option<Arc<tokio::sync::Semaphore>>,
    contact_sends: std::sync::atomic::AtomicUsize,
}
#[async_trait]
impl GcClient for FileClient {
    fn identity(&self) -> Identity {
        Identity {
            contact_card: ContactCard(vec![1]),
            safety_number: "fixture".into(),
        }
    }
    fn contact_identity(&self, card: &ContactCard) -> Result<Vec<u8>, SdkError> {
        Ok(card.0.clone())
    }
    fn subscribe_events(&self) -> tokio::sync::mpsc::Receiver<ClientEvent> {
        tokio::sync::mpsc::channel(1).1
    }
    async fn application_inbox(
        &self,
        _: u64,
        _: u16,
    ) -> Result<Vec<ApplicationDelivery>, SdkError> {
        Ok(vec![])
    }
    async fn submit_durable_opaque(
        &self,
        _: &ContactCard,
        _: &str,
        _: &[u8],
    ) -> Result<(), SdkError> {
        let gate = self
            .contact_gate
            .as_ref()
            .ok_or(SdkError::PermissionDenied)?;
        self.contact_sends.fetch_add(1, Ordering::SeqCst);
        gate.acquire()
            .await
            .map_err(|_| SdkError::ConnectionClosed)?
            .forget();
        Ok(())
    }
    async fn hosted_channels(&self, request: api::Request) -> Result<api::Reply, SdkError> {
        let mut client = self.client.lock().await;
        let result = match request {
            api::Request::List => {
                pump(&mut client).await;
                Ok(api::Reply::Channels(vec![client.view()]))
            }
            api::Request::FileEvents { limit, .. } => {
                client.file_events(limit).map(api::Reply::FileEvents)
            }
            api::Request::CommitFileEvents { through, .. } => {
                client.commit_file_events(through).map(|_| api::Reply::Done)
            }
            api::Request::SendIdentified { id, content, .. } => client
                .queue_send_identified(id, content)
                .map(api::Reply::Queued),
            api::Request::PutBlob {
                reference, bytes, ..
            } => client.blob(reference, Some(bytes)).await,
            api::Request::GetBlob { reference, .. } => {
                client.blob(reference, None).await.map(|mut reply| {
                    if self.tamper.load(Ordering::SeqCst) {
                        if let api::Reply::Blob(bytes) = &mut reply {
                            *bytes.last_mut().unwrap() ^= 1;
                        }
                    }
                    reply
                })
            }
            _ => Err("unsupported fixture operation".into()),
        };
        result.map_err(SdkError::Runtime)
    }
    async fn list_channels(&self) -> Result<Vec<JoinedChannel>, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn channel_roster(&self, _channel: &str) -> Result<Vec<ChannelMemberSummary>, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn public_channel_descriptor(
        &self,
        _channel: &str,
        _description: &str,
        _activity: ActivityBucket,
        _automatic_join: AutomaticJoinEndpoint,
        _expires_at_unix: u64,
    ) -> Result<PublicChannelDescriptor, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn send_direct(
        &self,
        _peer: &ContactCard,
        _body: &[u8],
        _via: Option<&ContactCard>,
    ) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn set_direct_presence(
        &self,
        _peer: &ContactCard,
        _mode: PresenceMode,
        _lease_secs: u32,
        _via: Option<&ContactCard>,
    ) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn set_direct_presence_opt_in(
        &self,
        _peer: &ContactCard,
        _enabled: bool,
        _via: Option<&ContactCard>,
    ) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn create_channel(
        &self,
        _channel: &str,
        _display_name: &str,
        _capacity: usize,
        _visibility: ChannelVisibility,
    ) -> Result<ChannelId, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn prepare_channel_join(&self, _display_name: &str) -> Result<JoinRequest, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn channel_key_package(&self, _request: JoinRequest) -> Result<Blob, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn admit_channel(
        &self,
        _channel: &str,
        _key_package: &Blob,
        _member_name: &str,
    ) -> Result<Blob, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn join_channel(
        &self,
        _request: JoinRequest,
        _channel: &str,
        _visibility: ChannelVisibility,
        _welcome: &Blob,
    ) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn send_channel(&self, _channel: &str, _body: &[u8]) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn set_channel_presence(
        &self,
        _channel: &str,
        _mode: PresenceMode,
        _lease_secs: u32,
    ) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn set_channel_presence_opt_in(
        &self,
        _channel: &str,
        _enabled: bool,
    ) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn send_channel_direct(
        &self,
        _channel: &str,
        _recipient_member_id: [u8; 32],
        _body: &[u8],
    ) -> Result<MessageId, SdkError> {
        Err(SdkError::PermissionDenied)
    }
    async fn remove_channel_member(
        &self,
        _channel: &str,
        _member_id: [u8; 32],
    ) -> Result<(), SdkError> {
        Err(SdkError::PermissionDenied)
    }
}

async fn file_service(home: &Path, client: Arc<FileClient>) -> Arc<ModernFileService> {
    let weak = Arc::downgrade(&client);
    ModernFileService::open(
        home,
        [67; 32],
        Arc::new(move || weak.upgrade().map(|c| c as Arc<dyn GcClient>)),
    )
    .await
    .unwrap()
}
async fn files(service: &ModernFileService) -> files::Snapshot {
    let files::Reply::Snapshot(snapshot) = service.request(files::Request::List).await.unwrap()
    else {
        panic!("snapshot")
    };
    snapshot
}
async fn wait_file(
    service: &ModernFileService,
    predicate: impl Fn(&files::FileInfo) -> bool,
) -> files::FileInfo {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(file) = files(service).await.files.into_iter().find(&predicate) {
                return file;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("hosted file state")
}
#[tokio::test]
async fn slow_contact_sends_remain_bounded_and_survive_control_interrupts() {
    use sha2::Digest as _;
    let server = private_dir();
    let home = private_dir();
    let cache = private_dir();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let client = Arc::new(FileClient {
        client: Mutex::new(owner(home.path(), service(server.path())).await),
        tamper: AtomicBool::new(false),
        contact_gate: Some(gate.clone()),
        contact_sends: Default::default(),
    });
    let files = file_service(cache.path(), client.clone()).await;
    let card = ContactCard(vec![2]);
    files
        .request(files::Request::Contacts(vec![card.clone()]))
        .await
        .unwrap();
    let peer = sha2::Sha256::digest(&card.0).into();
    for value in 1..=12 {
        let id = [value; 16];
        files
            .request(files::Request::Prepare {
                id,
                scope: files::Scope::Contact { peer },
                name: "slow.bin".into(),
                size_bytes: 1,
            })
            .await
            .unwrap();
        files
            .request(files::Request::WritePiece {
                id,
                piece: 0,
                bytes: vec![7],
            })
            .await
            .unwrap();
        files.request(files::Request::Commit { id }).await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        while client.contact_sends.load(Ordering::SeqCst) < 8 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("bounded concurrent sends start without blocking the profile");
    // Hold actual transport completion beyond the former three-second wrapper.
    // Replacing the same authorization must not cancel or duplicate those sends.
    for _ in 0..4 {
        tokio::time::timeout(
            Duration::from_secs(1),
            files.request(files::Request::Contacts(vec![card.clone()])),
        )
        .await
        .expect("control remains responsive during a slow send")
        .unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert_eq!(client.contact_sends.load(Ordering::SeqCst), 8);
    gate.add_permits(128);
    tokio::time::timeout(Duration::from_secs(3), async {
        while client.contact_sends.load(Ordering::SeqCst) < 12 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("real completions release the bounded send window");
    files.shutdown().await;
}
#[tokio::test]
async fn modern_hosted_file_rejects_tampering_and_resumes_with_publisher_offline() {
    let server = private_dir();
    let a = private_dir();
    let b = private_dir();
    let fa = private_dir();
    let fb = private_dir();
    let transport = service(server.path());
    let mut alice = owner(a.path(), transport.clone()).await;
    let channel = alice.archive.channel;
    let mut bob = joining(channel, "bob", b.path(), transport).await;
    pump(&mut bob).await;
    pump(&mut alice).await;
    let alice = Arc::new(FileClient {
        client: Mutex::new(alice),
        tamper: AtomicBool::new(false),
        contact_gate: None,
        contact_sends: Default::default(),
    });
    let bob = Arc::new(FileClient {
        client: Mutex::new(bob),
        tamper: AtomicBool::new(true),
        contact_gate: None,
        contact_sends: Default::default(),
    });
    let sender = file_service(fa.path(), alice.clone()).await;
    let receiver = file_service(fb.path(), bob.clone()).await;
    let id = [0x45; 16];
    let bytes: Vec<_> = (0..(2 * gcoms_sdk::sharing::PIECE_BYTES + 41))
        .map(|i| (i % 241) as u8)
        .collect();
    sender
        .request(files::Request::Prepare {
            id,
            scope: files::Scope::Hosted { channel },
            name: "sealed-report.bin".into(),
            size_bytes: bytes.len() as u64,
        })
        .await
        .unwrap();
    for (piece, bytes) in bytes.chunks(gcoms_sdk::sharing::PIECE_BYTES).enumerate() {
        sender
            .request(files::Request::WritePiece {
                id,
                piece: piece as u32,
                bytes: bytes.to_vec(),
            })
            .await
            .unwrap();
    }
    sender.request(files::Request::Commit { id }).await.unwrap();
    wait_file(&receiver, |f| f.id == id && f.status == Status::Offered).await;
    sender.shutdown().await;
    drop(sender);
    receiver
        .request(files::Request::Accept { id })
        .await
        .unwrap();
    let rejected = wait_file(&receiver, |f| f.id == id && f.error.is_some()).await;
    assert_eq!(rejected.verified_bytes, 0);
    assert_ne!(rejected.status, Status::Complete);
    bob.tamper.store(false, Ordering::SeqCst);
    receiver
        .request(files::Request::Resume { id })
        .await
        .unwrap();
    let partial = wait_file(&receiver, |f| {
        f.id == id && f.verified_bytes > 0 && f.verified_bytes < f.size_bytes
    })
    .await;
    receiver
        .request(files::Request::Pause { id })
        .await
        .unwrap();
    receiver.shutdown().await;
    drop(receiver);
    let raw = std::fs::read(fb.path().join("profile.v2")).unwrap();
    assert!(!raw
        .windows(b"sealed-report.bin".len())
        .any(|v| v == b"sealed-report.bin"));
    let receiver = file_service(fb.path(), bob.clone()).await;
    let restored = files(&receiver)
        .await
        .files
        .into_iter()
        .find(|f| f.id == id)
        .unwrap();
    assert_eq!(restored.status, Status::Paused);
    assert!(restored.verified_bytes >= partial.verified_bytes);
    receiver
        .request(files::Request::Resume { id })
        .await
        .unwrap();
    wait_file(&receiver, |f| f.id == id && f.status == Status::Complete).await;
    let mut exported = Vec::new();
    for piece in 0..3 {
        let files::Reply::Piece(bytes) = receiver
            .request(files::Request::ReadPiece { id, piece })
            .await
            .unwrap()
        else {
            panic!("piece")
        };
        exported.extend(bytes);
    }
    assert_eq!(exported, bytes);
    let sender = file_service(fa.path(), alice.clone()).await;
    wait_file(&sender, |f| f.id == id && f.completed_by == 1).await;
    sender.shutdown().await;
    receiver.shutdown().await;
}
