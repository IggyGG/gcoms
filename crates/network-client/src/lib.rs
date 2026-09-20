//! A single bootstrap policy shared by the daemon, UI host and Rust installer.
//! Public DNS locates services; installed signing roots and native TLS pins
//! establish identity. Private grants are never sent to an invitation's URL
//! until it agrees with independently verified network defaults.
pub mod names;
pub mod routing;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use fs2::FileExt;
use gcoms_network::{
    NetworkDefaults, NetworkInvitation, SignedNetworkDefaults, MAX_DOCUMENT_BYTES,
};
use gcoms_routing::bootstrap::BootstrapBundle;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;
use zeroize::Zeroizing;

pub type Result<T> = std::result::Result<T, String>;
const MAX_STATE_BYTES: usize = 512 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledNetwork {
    pub trusted_key_b64: String,
    pub signed_defaults: SignedNetworkDefaults,
}
impl InstalledNetwork {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_STATE_BYTES {
            return Err("installed network exceeds size bound".into());
        }
        serde_json::from_slice(bytes).map_err(|_| "invalid installed network".into())
    }
    pub fn defaults_at(&self, now: u64, minimum: u64) -> Result<NetworkDefaults> {
        self.signed_defaults.verify_at(
            &canonical_b64(&self.trusted_key_b64)?,
            &self.signed_defaults.defaults.network_id,
            now,
            minimum,
        )
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    #[serde(default)]
    version: u8,
    network_id: String,
    trust_hash: String,
    sequence: u64,
    signed_defaults: Option<SignedNetworkDefaults>,
    invitation: Option<NetworkInvitation>,
    #[serde(default)]
    names: names::NameState,
}

#[derive(Clone)]
pub struct NetworkClient {
    directory: Arc<PathBuf>,
    installed: Arc<InstalledNetwork>,
    http: reqwest::Client,
    local_transaction: Arc<std::sync::Mutex<()>>,
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn canonical_b64(value: &str) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "invalid base64url")?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err("noncanonical base64url".into());
    }
    Ok(bytes)
}
fn io_error(_: impl std::fmt::Display) -> String {
    "network state I/O failed".into()
}

fn private_directory(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => gcoms_private_fs::validate_private_dir(path, "network state"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Caller selects a private application directory, never repairs a
            // pre-existing directory with broad access.
            let parent = path.parent().ok_or("network state parent missing")?;
            gcoms_private_fs::validate_private_dir(parent, "network state parent")?;
            let builder = &mut std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(path) {
                Ok(()) => gcoms_private_fs::make_private(path, true)?,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(io_error(e)),
            }
            gcoms_private_fs::validate_private_dir(path, "network state")
        }
        Err(e) => Err(io_error(e)),
    }
}

fn private_open(path: &Path, create: bool) -> Result<File> {
    if path.exists() {
        gcoms_private_fs::validate_private_file(path, "network state file")?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(create).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(io_error)?;
    #[cfg(windows)]
    if create {
        gcoms_private_fs::make_private(path, false)?;
    }
    gcoms_private_fs::validate_private_file(path, "network state file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata().map_err(io_error)?;
        let current = std::fs::symlink_metadata(path).map_err(io_error)?;
        if opened.nlink() != 1 || opened.ino() != current.ino() || opened.dev() != current.dev() {
            return Err("network state file ownership changed".into());
        }
    }
    Ok(file)
}

impl NetworkClient {
    pub fn open(directory: &Path, installed: InstalledNetwork) -> Result<Self> {
        let document_time = now_unix().min(
            installed
                .signed_defaults
                .defaults
                .expires_at
                .saturating_sub(1),
        );
        installed.defaults_at(document_time, 0)?;
        private_directory(directory)?;
        // TLS uses native WebPKI verification; redirects cannot forward a grant.
        let http = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .user_agent("gchat-network/1")
            .build()
            .map_err(|_| "network HTTP client unavailable")?;
        let client = Self {
            directory: Arc::new(directory.to_path_buf()),
            installed: Arc::new(installed),
            http,
            local_transaction: Arc::new(std::sync::Mutex::new(())),
        };
        client.transaction(|_| Ok(()))?;
        Ok(client)
    }
    pub fn for_profile(profile: &Path, installed: InstalledNetwork) -> Result<Self> {
        let path = profile.with_extension("network");
        Self::open(&path, installed)
    }
    fn trust_hash(&self) -> Result<String> {
        let bytes = canonical_b64(&self.installed.trusted_key_b64)?;
        Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
    }
    fn transaction<T>(&self, action: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        // Cloned workers/UI calls share one short synchronous critical section.
        // The OS lock below still refuses another process/independent owner.
        let _local = self
            .local_transaction
            .lock()
            .map_err(|_| "network transaction lock poisoned")?;
        gcoms_private_fs::validate_private_dir(&self.directory, "network state")?;
        let lock = private_open(&self.directory.join("network.lock"), true)?;
        lock.try_lock_exclusive()
            .map_err(|_| "network state is busy")?;
        let path = self.directory.join("network.json");
        let original = match private_open(&path, false) {
            Ok(file) => {
                let mut bytes = Zeroizing::new(Vec::new());
                file.take((MAX_STATE_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(io_error)?;
                if bytes.len() > MAX_STATE_BYTES {
                    return Err("network state exceeds bound".into());
                }
                Some(bytes)
            }
            Err(_)
                if std::fs::symlink_metadata(&path)
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                None
            }
            Err(e) => return Err(e),
        };
        let mut state: State = if let Some(bytes) = &original {
            serde_json::from_slice(bytes).map_err(|_| "invalid retained network state")?
        } else {
            State {
                version: 1,
                network_id: self.installed.signed_defaults.defaults.network_id.clone(),
                trust_hash: self.trust_hash()?,
                sequence: self.installed.signed_defaults.defaults.sequence,
                ..Default::default()
            }
        };
        if state.version != 1
            || state.network_id != self.installed.signed_defaults.defaults.network_id
            || state.trust_hash != self.trust_hash()?
        {
            return Err("network state belongs to different installed trust".into());
        }
        // A newer installer is also an independently signed rollback floor.
        let installed_sequence = self.installed.signed_defaults.defaults.sequence;
        if state.sequence < installed_sequence {
            state.sequence = installed_sequence;
            state.signed_defaults = Some(self.installed.signed_defaults.clone());
        } else if state.sequence == installed_sequence
            && state
                .signed_defaults
                .as_ref()
                .is_some_and(|signed| signed != &self.installed.signed_defaults)
        {
            return Err("installed network defaults equivocation".into());
        }
        let result = action(&mut state)?;
        let bytes = Zeroizing::new(
            serde_json::to_vec(&state).map_err(|_| "network state encoding failed")?,
        );
        if original.as_deref().map(|v| &v[..]) != Some(&bytes[..]) {
            let mut temporary =
                tempfile::NamedTempFile::new_in(&*self.directory).map_err(io_error)?;
            gcoms_private_fs::make_private(temporary.path(), false)?;
            temporary.write_all(&bytes).map_err(io_error)?;
            temporary.as_file().sync_all().map_err(io_error)?;
            temporary.persist(&path).map_err(io_error)?;
            #[cfg(unix)]
            File::open(&*self.directory)
                .and_then(|f| f.sync_all())
                .map_err(io_error)?;
        }
        drop(lock);
        Ok(result)
    }
    fn selected_defaults(&self, state: &State, now: u64) -> Result<NetworkDefaults> {
        let signed = state
            .signed_defaults
            .as_ref()
            .unwrap_or(&self.installed.signed_defaults);
        signed.verify_at(
            &canonical_b64(&self.installed.trusted_key_b64)?,
            &state.network_id,
            now,
            state.sequence,
        )
    }
    pub fn current_defaults(&self) -> Result<NetworkDefaults> {
        self.transaction(|state| self.selected_defaults(state, now_unix()))
    }
    pub fn import_invitation(&self, code: &str) -> Result<()> {
        let now = now_unix();
        let invitation = NetworkInvitation::decode_at(code.trim(), now)?;
        self.transaction(|state| {
            let defaults = self.selected_defaults(state, now)?;
            validate_invitation(&invitation, &defaults, now)?;
            state.sequence = defaults.sequence;
            state.invitation = Some(invitation);
            Ok(())
        })
    }
    pub fn import_invitation_file(&self, path: &Path) -> Result<()> {
        gcoms_private_fs::validate_private_parent(path, "network invitation")?;
        let mut raw = Zeroizing::new(String::new());
        private_open(path, false)?
            .take((MAX_DOCUMENT_BYTES * 2) as u64)
            .read_to_string(&mut raw)
            .map_err(io_error)?;
        self.import_invitation(&raw)
    }
    pub fn has_invitation(&self) -> Result<bool> {
        self.transaction(|state| Ok(state.invitation.is_some()))
    }
    /// Defaults are public. An expired cached document may only locate a
    /// replacement signed by the original root, never authorize private traffic.
    pub async fn refresh_defaults(&self, deadline: Instant) -> Result<()> {
        let urls = self.transaction(|state| {
            let signed = state
                .signed_defaults
                .as_ref()
                .unwrap_or(&self.installed.signed_defaults);
            let verified = signed.verify_at(
                &canonical_b64(&self.installed.trusted_key_b64)?,
                &state.network_id,
                now_unix().min(signed.defaults.expires_at.saturating_sub(1)),
                state.sequence,
            )?;
            Ok(verified.provider_urls)
        })?;
        gcoms_network::validate_provider_urls(&urls)?;
        let mut last = "network defaults providers unavailable".to_string();
        let count = urls.len();
        for (index, base) in urls.into_iter().enumerate() {
            if Instant::now() >= deadline {
                break;
            }
            let attempt = async {
                let response = self
                    .http
                    .get(format!("{}v1/network-defaults", base))
                    .send()
                    .await
                    .map_err(|_| "network defaults unreachable")?;
                if !response.status().is_success() {
                    return Err("network defaults refused".into());
                }
                let bytes = bounded_body(response).await?;
                let signed: SignedNetworkDefaults = serde_json::from_slice(&bytes)
                    .map_err(|_| "invalid network defaults response")?;
                self.transaction(|state| {
                    let value = signed.verify_at(
                        &canonical_b64(&self.installed.trusted_key_b64)?,
                        &state.network_id,
                        now_unix(),
                        state.sequence,
                    )?;
                    let previous = state
                        .signed_defaults
                        .as_ref()
                        .unwrap_or(&self.installed.signed_defaults);
                    if value.sequence == state.sequence && &signed != previous {
                        return Err("network defaults equivocation".into());
                    }
                    state.sequence = value.sequence;
                    state.signed_defaults = Some(signed);
                    Ok(())
                })
            };
            match tokio::time::timeout_at(provider_deadline(deadline, count - index), attempt).await
            {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(error)) => last = error,
                Err(_) => last = "network defaults attempt timed out".into(),
            }
        }
        Err(last)
    }
    pub async fn fetch_routing(&self, deadline: Instant) -> Result<BootstrapBundle> {
        self.fetch_routing_with(deadline, 2, routing::decode_legacy_response)
            .await
    }

    /// Fetch only authenticated current-protocol introductions. Envelope v3
    /// explicitly carries GC/2; envelope v2 is the legacy GCRB1 protocol.
    #[cfg(feature = "experimental-gc2")]
    pub async fn fetch_gc2_routing(
        &self,
        deadline: Instant,
    ) -> Result<gcoms_routing::gc2::directory::BootstrapBundle> {
        self.fetch_routing_with(deadline, 3, routing::decode_gc2_response)
            .await
    }

    async fn fetch_routing_with<T>(
        &self,
        deadline: Instant,
        version: u8,
        decode: fn(&[u8]) -> Result<T>,
    ) -> Result<T> {
        // A provider failure doesn't invalidate a still-valid signed cache.
        // Public document refresh gets at most one quarter of the remaining
        // budget, leaving room for private provisioning and another provider.
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("network bootstrap deadline elapsed".into());
        }
        let refresh_deadline =
            deadline.min(Instant::now() + (remaining / 4).min(Duration::from_secs(3)));
        let _ = self.refresh_defaults(refresh_deadline).await;
        let (defaults, invitation) = self.transaction(|state| {
            let defaults = self.selected_defaults(state, now_unix())?;
            let invitation = state
                .invitation
                .clone()
                .ok_or("Enter a network invitation to connect.")?;
            validate_retained_invitation(&invitation, &defaults, now_unix())?;
            Ok((defaults, invitation))
        })?;
        let request_id = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>());
        let mut last = "network bootstrap providers unavailable".to_string();
        let count = defaults.provider_urls.len();
        for (index, base) in defaults.provider_urls.into_iter().enumerate() {
            if Instant::now() >= deadline {
                break;
            }
            let attempt = async {
                let response = self
                    .http
                    .post(format!("{}v1/relay-provisions", base))
                    .bearer_auth(&invitation.grant)
                    .json(&serde_json::json!({"request_id":request_id,"supported_versions":[version]}))
                    .send()
                    .await
                    .map_err(|_| "network bootstrap unreachable")?;
                if !response.status().is_success() {
                    return Err(format!(
                        "network bootstrap refused ({})",
                        response.status().as_u16()
                    ));
                }
                decode(&bounded_body(response).await?)
            };
            match tokio::time::timeout_at(provider_deadline(deadline, count - index), attempt).await
            {
                Ok(Ok(bundle)) => return Ok(bundle),
                Ok(Err(error)) => last = error,
                Err(_) => last = "network bootstrap attempt timed out".into(),
            }
        }
        Err(last)
    }
}

fn provider_deadline(deadline: Instant, remaining_providers: usize) -> Instant {
    let now = Instant::now();
    let share = deadline.saturating_duration_since(now) / remaining_providers.max(1) as u32;
    now + share.min(Duration::from_secs(10))
}
fn validate_retained_invitation(
    invitation: &NetworkInvitation,
    defaults: &NetworkDefaults,
    now: u64,
) -> Result<()> {
    if invitation.expires_at <= now || invitation.network_id != defaults.network_id {
        return Err("network invitation expired or changed network".into());
    }
    Ok(())
}
fn validate_invitation(
    invitation: &NetworkInvitation,
    defaults: &NetworkDefaults,
    now: u64,
) -> Result<()> {
    validate_retained_invitation(invitation, defaults, now)?;
    if invitation.provider_urls != defaults.provider_urls {
        return Err("network invitation does not match current installed network".into());
    }
    Ok(())
}
async fn bounded_body(mut response: reqwest::Response) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|n| n > MAX_DOCUMENT_BYTES as u64)
    {
        return Err("network response exceeds bound".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "network response failed")?
    {
        if chunk.len() > MAX_DOCUMENT_BYTES.saturating_sub(bytes.len()) {
            return Err("network response exceeds bound".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gcoms_crypto::IdentityKeypair;
    const DEFAULT_PROVIDER_URLS: [&str; 2] = [
        "https://bootstrap-a.example/",
        "https://bootstrap-b.example/",
    ];
    pub(super) fn installed() -> InstalledNetwork {
        let signer = IdentityKeypair::from_seed([7; 32]);
        let now = now_unix();
        let defaults = NetworkDefaults {
            version: 1,
            network_id: "gchat.boo".into(),
            sequence: 5,
            issued_at: now - 10,
            expires_at: now + 3600,
            provider_urls: DEFAULT_PROVIDER_URLS
                .iter()
                .map(|v| (*v).to_string())
                .collect(),
            founders: vec![gcoms_network::Founder {
                name: "r1.relays.gchat.boo".into(),
                service_id: [3; 32],
                address_hints: vec!["8.8.8.8:4433".parse().unwrap()],
            }],
            dns_domain: "gchat.boo".into(),
        };
        InstalledNetwork {
            trusted_key_b64: URL_SAFE_NO_PAD.encode(signer.public_bytes()),
            signed_defaults: SignedNetworkDefaults::sign(defaults, &signer, vec![]).unwrap(),
        }
    }
    pub(super) fn invitation() -> NetworkInvitation {
        NetworkInvitation {
            version: 1,
            network_id: "gchat.boo".into(),
            provider_urls: DEFAULT_PROVIDER_URLS
                .iter()
                .map(|v| (*v).to_string())
                .collect(),
            grant: URL_SAFE_NO_PAD.encode([9; 32]),
            expires_at: now_unix() + 1800,
        }
    }
    fn client(root: &Path) -> NetworkClient {
        gcoms_private_fs::make_private(root, true).unwrap();
        NetworkClient::open(&root.join("network"), installed()).unwrap()
    }
    #[test]
    fn cloned_workers_serialize_without_weakening_external_lock_refusal() {
        let temp = tempfile::tempdir().unwrap();
        let network = client(temp.path());
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let network = network.clone();
                std::thread::spawn(move || {
                    for _ in 0..25 {
                        network.configure_opt_in(true).unwrap();
                        assert!(network.name_status().unwrap().opted_in);
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let lock = private_open(&network.directory.join("network.lock"), false).unwrap();
        lock.try_lock_exclusive().unwrap();
        assert_eq!(network.name_status().unwrap_err(), "network state is busy");
        drop(lock);
        network.configure_opt_in(false).unwrap();
        assert!(!network.name_status().unwrap().opted_in);
    }
    #[test]
    fn invitation_survives_reopen_without_identity_or_new_grant() {
        let temp = tempfile::tempdir().unwrap();
        let first = client(temp.path());
        let selected = invitation();
        first
            .import_invitation(&selected.encode().unwrap())
            .unwrap();
        let bytes = std::fs::read(temp.path().join("network/network.json")).unwrap();
        let second = client(temp.path());
        assert!(second.has_invitation().unwrap());
        second
            .transaction(|state| {
                assert!(state.invitation.as_ref() == Some(&selected));
                assert_eq!(state.sequence, 5);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            bytes,
            std::fs::read(temp.path().join("network/network.json")).unwrap()
        );
    }
    #[test]
    fn wrong_origin_network_and_expired_invitation_preserve_state() {
        let temp = tempfile::tempdir().unwrap();
        let c = client(temp.path());
        c.import_invitation(&invitation().encode().unwrap())
            .unwrap();
        let before = std::fs::read(temp.path().join("network/network.json")).unwrap();
        for index in 0..3 {
            let mut value = invitation();
            match index {
                0 => value.provider_urls = vec!["https://untrusted.example/".into()],
                1 => value.network_id = "elsewhere.example".into(),
                _ => value.expires_at = 1,
            };
            assert!(c.import_invitation(&value.encode().unwrap()).is_err());
            assert_eq!(
                before,
                std::fs::read(temp.path().join("network/network.json")).unwrap()
            );
        }
    }
    #[test]
    fn cached_rollback_and_changed_installed_root_refuse() {
        let temp = tempfile::tempdir().unwrap();
        let c = client(temp.path());
        c.transaction(|state| {
            state.sequence = 6;
            Ok(())
        })
        .unwrap();
        assert!(c.current_defaults().is_err());
        assert!(c
            .import_invitation(&invitation().encode().unwrap())
            .is_err());
        let mut other = installed();
        let signer = IdentityKeypair::from_seed([8; 32]);
        other.trusted_key_b64 = URL_SAFE_NO_PAD.encode(signer.public_bytes());
        other.signed_defaults =
            SignedNetworkDefaults::sign(other.signed_defaults.defaults, &signer, vec![]).unwrap();
        assert!(NetworkClient::open(&temp.path().join("network"), other).is_err());
    }
    #[test]
    fn busy_writer_does_not_wait_or_overwrite() {
        let temp = tempfile::tempdir().unwrap();
        let c = client(temp.path());
        let lock = private_open(&temp.path().join("network/network.lock"), false).unwrap();
        lock.try_lock_exclusive().unwrap();
        assert!(c
            .import_invitation(&invitation().encode().unwrap())
            .unwrap_err()
            .contains("busy"));
        drop(lock);
        assert!(!c.has_invitation().unwrap());
    }
    #[cfg(unix)]
    #[test]
    fn symlink_hardlink_and_public_grant_file_refuse() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let temp = tempfile::tempdir().unwrap();
        let c = client(temp.path());
        let file = temp.path().join("invitation");
        std::fs::write(&file, invitation().encode().unwrap()).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(c.import_invitation_file(&file).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = temp.path().join("link");
        symlink(&file, &link).unwrap();
        assert!(c.import_invitation_file(&link).is_err());
        std::fs::remove_file(link).unwrap();
        std::fs::hard_link(&file, temp.path().join("alias")).unwrap();
        assert!(c.import_invitation_file(&file).is_err());
    }
}

#[cfg(test)]
mod tls_tests;
