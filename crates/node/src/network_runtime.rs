//! CLI-owned, bounded network maintenance. Neither path delays serving GC.
use gcoms_network_client::NetworkClient;
use gcoms_node::node::NodeHandle;
use gcoms_routing::bootstrap::BootstrapBundle;
use rand::Rng;
use std::{future::Future, path::Path, path::PathBuf, time::Duration};
use tokio::{task::JoinHandle, time::Instant};

type Result<T> = std::result::Result<T, String>;

#[derive(Default)]
pub(crate) struct Selection {
    invitation: Option<PathBuf>,
    network_config: Option<PathBuf>,
    server_label: Option<String>,
    opted_in: Option<bool>,
}

impl Selection {
    pub(crate) fn parse(args: &[String]) -> Result<Self> {
        let mut selected = Self::default();
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--network-config" => {
                    if selected.network_config.is_some() {
                        return Err("duplicate --network-config".into());
                    }
                    selected.network_config = Some(PathBuf::from(value(&mut args)?));
                }
                "--network-invitation-file" => {
                    if selected.invitation.is_some() {
                        return Err("duplicate --network-invitation-file".into());
                    }
                    selected.invitation = Some(PathBuf::from(value(&mut args)?));
                }
                "--dns-server-label" => {
                    if selected.server_label.is_some() {
                        return Err("duplicate --dns-server-label".into());
                    }
                    let label = value(&mut args)?;
                    if !(1..=8).any(|n| label == format!("r{n}")) {
                        return Err("DNS server label must be r1 through r8".into());
                    }
                    selected.server_label = Some(label);
                }
                "--dns-opt-in" | "--dns-opt-out" => {
                    if selected.opted_in.is_some() {
                        return Err("select exactly one DNS consent flag".into());
                    }
                    selected.opted_in = Some(arg == "--dns-opt-in");
                }
                _ => {}
            }
        }
        Ok(selected)
    }

    pub(crate) fn open(&self, profile: &Path) -> Result<NetworkClient> {
        let path = self
            .network_config
            .as_ref()
            .ok_or("--network-config is required for automatic network discovery")?;
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(|_| "cannot read network configuration")?
            .take((gcoms_network::MAX_DOCUMENT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read network configuration")?;
        let network = NetworkClient::for_profile(
            profile,
            gcoms_network_client::InstalledNetwork::from_json(&bytes)?,
        )?;
        if self.configure(&network).is_err() {
            // In particular, an already-persisted opt-out must still get its
            // removal worker when another selected input cannot be applied.
            eprintln!(
                "gcnode: network selection not fully applied; retained maintenance continues"
            );
        }
        Ok(network)
    }

    fn configure(&self, network: &NetworkClient) -> Result<()> {
        // Persist withdrawal before any other configuration that can fail.
        if self.opted_in == Some(false) {
            network.configure_opt_in(false)?;
        }
        if let Some(label) = &self.server_label {
            network.configure_server_label(Some(label))?;
        }
        if let Some(path) = &self.invitation {
            network.import_invitation_file(path)?;
        }
        if self.opted_in == Some(true) {
            network.configure_opt_in(true)?;
        }
        // Absent flags preserve retained consent and label. New state defaults
        // to an ordinary client name with DNS disabled.
        Ok(())
    }
}

fn value(args: &mut std::slice::Iter<'_, String>) -> Result<String> {
    args.next()
        .filter(|value| !value.is_empty() && !value.starts_with("--"))
        .cloned()
        .ok_or_else(|| "network flag requires a value".into())
}

// These small seams exercise scheduling and cancellation without contacting a
// real provider or printing a private invitation/listener proof in fixtures.
trait Network: Clone + Send + Sync + 'static {
    fn has_invitation(&self) -> Result<bool>;
    fn opted_in(&self) -> Result<bool>;
    fn name_wake(&self) -> Result<Option<Duration>>;
    fn fetch(&self, deadline: Instant) -> impl Future<Output = Result<BootstrapBundle>> + Send;
    fn flush(&self, deadline: Instant) -> impl Future<Output = Result<()>> + Send;
    fn update(
        &self,
        bundle: BootstrapBundle,
        deadline: Instant,
    ) -> impl Future<Output = Result<()>> + Send;
}

impl Network for NetworkClient {
    fn has_invitation(&self) -> Result<bool> {
        self.has_invitation()
    }
    fn opted_in(&self) -> Result<bool> {
        Ok(self.name_status()?.opted_in)
    }
    fn name_wake(&self) -> Result<Option<Duration>> {
        let status = self.name_status()?;
        let expires = status
            .registration
            .filter(|_| status.opted_in && !status.removed)
            .map(|registration| registration.lease_expires_at);
        Ok(lease_wake(
            expires,
            status.pending,
            gcoms_network_client::now_unix(),
        ))
    }
    async fn fetch(&self, deadline: Instant) -> Result<BootstrapBundle> {
        self.fetch_routing(deadline).await
    }
    async fn flush(&self, deadline: Instant) -> Result<()> {
        self.flush_name(deadline).await.map(|_| ())
    }
    async fn update(&self, bundle: BootstrapBundle, deadline: Instant) -> Result<()> {
        self.update_listener(&bundle, deadline).await.map(|_| ())
    }
}

trait Node: Clone + Send + Sync + 'static {
    fn cached(&self) -> bool;
    fn introduction(&self) -> Result<Option<BootstrapBundle>>;
    fn inbox(&self, deadline: Instant) -> impl Future<Output = Result<()>> + Send;
    fn install(&self, bundle: BootstrapBundle) -> impl Future<Output = Result<()>> + Send;
}

impl Node for NodeHandle {
    fn cached(&self) -> bool {
        self.routing_bootstrap().is_ok()
    }
    fn introduction(&self) -> Result<Option<BootstrapBundle>> {
        self.local_relay_introduction()
    }
    async fn inbox(&self, deadline: Instant) -> Result<()> {
        self.wait_for_inbox(deadline).await
    }
    async fn install(&self, bundle: BootstrapBundle) -> Result<()> {
        self.install_routing_bootstrap(bundle).await
    }
}

pub(crate) struct Worker {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl Worker {
    pub(crate) fn start(node: NodeHandle, network: NetworkClient) -> Self {
        Self::spawn(node, network)
    }

    fn spawn(node: impl Node, network: impl Network) -> Self {
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            tokio::select! {
                _ = stopped => {},
                _ = async {
                    tokio::join!(bootstrap_loop(&node, &network), names_loop(&node, &network));
                } => {},
            }
        });
        Self {
            stop: Some(stop),
            task,
        }
    }

    pub(crate) async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if tokio::time::timeout(Duration::from_secs(2), &mut self.task)
            .await
            .is_err()
        {
            self.task.abort();
            let _ = (&mut self.task).await;
        }
        // Stopping a process does not withdraw consent. An interrupted HTTP
        // mutation remains journaled by NetworkClient for the next boot.
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn bootstrap_cycle(
    node: &impl Node,
    network: &impl Network,
    deadline: Instant,
) -> Result<()> {
    let cached_deadline = deadline.min(Instant::now() + Duration::from_secs(30));
    if node.cached() && node.inbox(cached_deadline).await.is_ok() {
        return Ok(());
    }
    if !network.has_invitation()? {
        return Ok(());
    }
    let bundle = network.fetch(deadline).await?;
    node.install(bundle).await?;
    node.inbox(deadline).await
}

async fn names_cycle(node: &impl Node, network: &impl Network, deadline: Instant) -> Result<()> {
    // Required even without a listener or current consent: an earlier opt-out
    // can have a retained exact removal that must survive downtime.
    network.flush(deadline).await?;
    if network.opted_in()? {
        if let Some(bundle) = node.introduction()? {
            network.update(bundle, deadline).await?;
        }
    }
    Ok(())
}

async fn bootstrap_loop(node: &impl Node, network: &impl Network) {
    let mut retry = Retry::default();
    loop {
        let deadline = Instant::now() + Duration::from_secs(45);
        let success = matches!(
            tokio::time::timeout_at(deadline, bootstrap_cycle(node, network, deadline)).await,
            Ok(Ok(()))
        );
        retry.report(success, "gcnode: private network recovery deferred");
        tokio::time::sleep(retry.delay(success)).await;
    }
}

async fn names_loop(node: &impl Node, network: &impl Network) {
    let mut retry = Retry::default();
    loop {
        let deadline = Instant::now() + Duration::from_secs(20);
        let success = matches!(
            tokio::time::timeout_at(deadline, names_cycle(node, network, deadline)).await,
            Ok(Ok(()))
        );
        retry.report(success, "gcnode: DNS maintenance deferred");
        tokio::time::sleep(name_delay(network, &mut retry, success)).await;
    }
}

fn lease_wake(expires: Option<u64>, pending: bool, now: u64) -> Option<Duration> {
    let lease = expires.map(|expiry| Duration::from_secs((expiry.saturating_sub(now) / 2).max(1)));
    if pending {
        Some(
            lease
                .unwrap_or(Duration::from_secs(5))
                .min(Duration::from_secs(5)),
        )
    } else {
        lease
    }
}

fn name_delay(network: &impl Network, retry: &mut Retry, success: bool) -> Duration {
    let delay = retry.delay(success).min(Duration::from_secs(300));
    // The backend may grant only the final seconds of the current listener
    // proof. Both successful and failed attempts must honor that actual lease.
    network
        .name_wake()
        .ok()
        .flatten()
        .map_or(delay, |limit| delay.min(limit))
}

#[derive(Default)]
struct Retry {
    failures: u32,
    reported: bool,
}

impl Retry {
    fn report(&mut self, success: bool, message: &str) {
        if !success && !self.reported {
            // Fixed messages only: never emit provider errors, proofs, grants,
            // name credentials or contact-bearing descriptors.
            eprintln!("{message}");
        }
        self.reported = !success;
    }
    fn delay(&mut self, success: bool) -> Duration {
        let base = if success {
            self.failures = 0;
            30
        } else {
            let seconds = (5u64 << self.failures.min(6)).min(300);
            self.failures = self.failures.saturating_add(1);
            seconds
        };
        Duration::from_millis(rand::thread_rng().gen_range(base * 1000..=base * 1250))
    }
}

#[cfg(test)]
mod tests;
