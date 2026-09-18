//! Resource-bounded private circuit service on the existing TP1 listener.
use crate::{
    carrier::{self, CarrierConfig, Records},
    directory::RELAY_BYTES,
    route::now_unix,
    wire::{Kind, Target},
    Directory, Relay, Result,
};
use gcoms_transport::{
    connector::BoxStream,
    server::{AcceptedDuplex, DuplexHandler},
};
use hmac::{Hmac, Mac};
use rand::seq::SliceRandom;
use sha2::Sha256;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

/// Returns a fresh private inbox grant, with no GC user identity in the request.
pub type ProvisionHandler = Arc<dyn Fn() -> Result<Vec<u8>> + Send + Sync>;
pub type FixtureCatalogResolver = Arc<dyn Fn(&str) -> Vec<SocketAddr> + Send + Sync>;

#[derive(Clone)]
pub struct ServicePolicy {
    pub carrier: CarrierConfig,
    pub max_circuits: usize,
    /// Explicitly admitted numeric targets. Production defaults reject special
    /// networks; local test allowances must be supplied deliberately.
    pub target_allowed: Arc<dyn Fn(SocketAddr) -> bool + Send + Sync>,
    pub catalog_origins: Vec<String>,
    pub provision: Option<ProvisionHandler>,
    /// Explicit test-only DNS substitute. Production leaves this absent.
    pub fixture_catalog_resolver: Option<FixtureCatalogResolver>,
    /// Optional native full-node reachability gate. Discovery/probes remain
    /// available, while transit is refused until independent admission succeeds.
    pub transit_ready: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl Default for ServicePolicy {
    fn default() -> Self {
        Self {
            carrier: CarrierConfig::default(),
            max_circuits: 128,
            target_allowed: Arc::new(|addr| public_ip(addr.ip())),
            catalog_origins: Vec::new(),
            provision: None,
            fixture_catalog_resolver: None,
            transit_ready: None,
        }
    }
}

pub struct RelayService {
    addr: Mutex<SocketAddr>,
    service_id: [u8; 32],
    secret: Zeroizing<[u8; 32]>,
    directory: Arc<Directory>,
    policy: ServicePolicy,
    slots: Arc<Semaphore>,
    #[cfg(feature = "experimental-gc2")]
    gc2_bulk_slots: Arc<Semaphore>,
    #[cfg(feature = "experimental-gc2")]
    gc2_control_slots: Arc<Semaphore>,
    #[cfg(feature = "experimental-gc2")]
    gc2_directory: Arc<crate::gc2::directory::Directory>,
    private: Mutex<PrivateState>,
    probes: Semaphore,
    catalog_origins: Mutex<Vec<String>>,
}

struct PrivateState {
    window: Instant,
    operations: usize,
    provisions: HashMap<[u8; 32], (Instant, Zeroizing<Vec<u8>>)>,
}

impl PrivateState {
    fn admit(&mut self) -> Result<()> {
        if self.window.elapsed() >= Duration::from_secs(60) {
            self.window = Instant::now();
            self.operations = 0;
        }
        if self.operations >= 64 {
            return Err("private service operation limit".into());
        }
        self.operations += 1;
        Ok(())
    }
}

impl RelayService {
    /// `secret` belongs to the independent relay service, never to a person's
    /// contact or a queue. The owner retains it only in its encrypted archive.
    pub fn new(
        addr: SocketAddr,
        service_id: [u8; 32],
        secret: [u8; 32],
        directory: Arc<Directory>,
        policy: ServicePolicy,
    ) -> Result<Arc<Self>> {
        policy.carrier.validate()?;
        if secret == [0; 32]
            || service_id == [0; 32]
            || !(1..=128).contains(&policy.max_circuits)
            || policy.catalog_origins.len() > 8
            || policy
                .catalog_origins
                .iter()
                .any(|host| !crate::wire::valid_host(host))
        {
            return Err("invalid relay service policy".into());
        }
        Ok(Arc::new(Self {
            addr: Mutex::new(addr),
            service_id,
            secret: Zeroizing::new(secret),
            directory,
            slots: Arc::new(Semaphore::new(policy.max_circuits)),
            #[cfg(feature = "experimental-gc2")]
            gc2_bulk_slots: Arc::new(Semaphore::new(policy.max_circuits.saturating_sub(1))),
            #[cfg(feature = "experimental-gc2")]
            gc2_control_slots: Arc::new(Semaphore::new(4)),
            #[cfg(feature = "experimental-gc2")]
            gc2_directory: Arc::new(crate::gc2::directory::Directory::with_address_policy(
                policy.target_allowed.clone(),
            )),
            catalog_origins: Mutex::new(policy.catalog_origins.clone()),
            policy,
            private: Mutex::new(PrivateState {
                window: Instant::now(),
                operations: 0,
                provisions: HashMap::new(),
            }),
            probes: Semaphore::new(4),
        }))
    }

    fn capability(&self, purpose: &[u8], epoch: u64) -> [u8; 32] {
        let mut hash =
            Hmac::<Sha256>::new_from_slice(self.secret.as_ref()).expect("fixed HMAC key");
        hash.update(b"ghost.circuit.capability.v1\0");
        hash.update(purpose);
        hash.update(&epoch.to_be_bytes());
        hash.finalize().into_bytes().into()
    }

    pub fn introduction(&self, now: u64) -> Relay {
        let epoch = now / 3600;
        Relay {
            addr: self.address(),
            service_id: self.service_id,
            reentry_cap: self.capability(b"reentry", 0),
            circuit_cap: self.capability(b"circuit", epoch),
            expires_at: (epoch + 1) * 3600,
        }
    }

    /// Explicit experimental GC/2 authority; GC/1 circuit/re-entry capabilities
    /// cannot authenticate this service. Private discovery migration is separate.
    #[cfg(feature = "experimental-gc2")]
    pub fn gc2_entry_descriptor(&self, now: u64) -> crate::gc2::entry::EntryDescriptor {
        let epoch = now / 3600;
        let mut hash =
            Hmac::<Sha256>::new_from_slice(self.secret.as_ref()).expect("fixed HMAC key");
        hash.update(b"ghost.gct2.entry.v2\0");
        hash.update(&self.service_id);
        hash.update(&epoch.to_be_bytes());
        crate::gc2::entry::EntryDescriptor {
            addr: self.address(),
            service_id: self.service_id,
            entry_cap: hash.finalize().into_bytes().into(),
            expires_at: (epoch + 1) * 3600,
        }
    }

    #[cfg(feature = "experimental-gc2")]
    pub fn gc2_transit_descriptor(&self, now: u64) -> crate::gc2::transit::TransitDescriptor {
        let epoch = now / 3600;
        let mut hash =
            Hmac::<Sha256>::new_from_slice(self.secret.as_ref()).expect("fixed HMAC key");
        hash.update(b"ghost.gct2.transit.v2\0");
        hash.update(&self.service_id);
        hash.update(&epoch.to_be_bytes());
        crate::gc2::transit::TransitDescriptor {
            addr: self.address(),
            service_id: self.service_id,
            transit_cap: hash.finalize().into_bytes().into(),
            expires_at: (epoch + 1) * 3600,
        }
    }

    /// Explicit versioned bootstrap authority. Re-entry survives hourly circuit
    /// expiry; its domain is separate from GC/1, entry and middle capabilities.
    #[cfg(feature = "experimental-gc2")]
    pub fn gc2_introduction(&self, now: u64) -> crate::gc2::directory::Introduction {
        let entry = self.gc2_entry_descriptor(now);
        let transit = self.gc2_transit_descriptor(now);
        let mut hash =
            Hmac::<Sha256>::new_from_slice(self.secret.as_ref()).expect("fixed HMAC key");
        hash.update(b"ghost.gct2.reentry.v2\0");
        hash.update(&self.service_id);
        crate::gc2::directory::Introduction {
            addr: entry.addr,
            service_id: entry.service_id,
            reentry_cap: hash.finalize().into_bytes().into(),
            entry_cap: entry.entry_cap,
            transit_cap: transit.transit_cap,
            expires_at: entry.expires_at,
        }
    }

    #[cfg(feature = "experimental-gc2")]
    pub fn gc2_directory(&self) -> &Arc<crate::gc2::directory::Directory> {
        &self.gc2_directory
    }

    #[cfg(feature = "experimental-gc2")]
    async fn gc2_introductions(
        &self,
        mut body: h2::RecvStream,
        mut response: h2::server::SendResponse<bytes::Bytes>,
    ) -> Result<()> {
        use crate::gc2::{
            directory::{BootstrapBundle, MAX_INTRODUCTIONS},
            discovery::REQUEST,
        };
        use gcoms_core::{gc2::NaturalCell, CellType, HEADER_LEN};
        use gcoms_transport::{gc2::status_cell, hop::HopReply};
        let permit = self.gc2_control_slots.clone().try_acquire_owned();
        let admitted = permit.is_ok()
            && self
                .private
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .admit()
                .is_ok();
        let cell = if admitted {
            let bytes =
                gcoms_transport::server::read_body(&mut body, HEADER_LEN + REQUEST.len()).await?;
            let request = NaturalCell::decode(&bytes)?;
            if request.kind() != CellType::Pex
                || request.flags() != 0
                || request.payload() != REQUEST
            {
                return Err("invalid GC/2 private discovery request".into());
            }
            let now = now_unix();
            let own = self.gc2_introduction(now);
            let mut relays = self
                .gc2_directory
                .eligible(&[(own.addr, own.service_id)], now)?;
            relays.shuffle(&mut rand::thread_rng());
            relays.truncate(MAX_INTRODUCTIONS - 1);
            relays.insert(0, own);
            let bytes = BootstrapBundle { relays }.encode()?;
            NaturalCell::new(CellType::Pex, 0, bytes.to_vec())?
        } else {
            status_cell(HopReply::Overloaded)
        };
        let headers = http::Response::builder()
            .status(200)
            .header("content-type", "application/octet-stream")
            .body(())?;
        let mut send = response.send_response(headers, false)?;
        send.send_data(bytes::Bytes::from(cell.encode()), true)?;
        Ok(())
    }

    #[cfg(feature = "experimental-gc2")]
    fn gc2_target_connector(self: &Arc<Self>) -> crate::gc2::mux::TargetConnector {
        let service = self.clone();
        Arc::new(move |target, class| {
            let service = service.clone();
            Box::pin(async move {
                let mut permits = Vec::with_capacity(2);
                if class == gcoms_core::TrafficClass::Bulk {
                    permits.push(service.gc2_bulk_slots.clone().try_acquire_owned()?);
                }
                permits.push(service.slots.clone().try_acquire_owned()?);
                let io = service.connect_target(target).await?;
                Ok(crate::gc2::entry::hold_capacity(io, permits))
            })
        })
    }

    /// Attach with `Tp1Server::with_dispatch_factory` to fix entry, transit,
    /// control or terminal role before any registered endpoint can run. A
    /// protected entry fixes its profile and shares one 16-circuit budget.
    #[cfg(feature = "experimental-gc2")]
    pub fn gc2_handler_factory(
        self: &Arc<Self>,
    ) -> gcoms_transport::server::DispatchHandlerFactory {
        self.gc2_dispatch_factory(None)
    }

    /// Compose a natural terminal service under the same connection role gate.
    /// An accepted terminal path must still authenticate its complete envelope.
    #[cfg(feature = "experimental-gc2")]
    pub fn gc2_handler_factory_with_terminal(
        self: &Arc<Self>,
        terminal: DuplexHandler,
    ) -> gcoms_transport::server::DispatchHandlerFactory {
        self.gc2_dispatch_factory(Some(terminal))
    }

    #[cfg(feature = "experimental-gc2")]
    fn gc2_dispatch_factory(
        self: &Arc<Self>,
        terminal: Option<DuplexHandler>,
    ) -> gcoms_transport::server::DispatchHandlerFactory {
        use crate::gc2::{entry, transit};
        use gcoms_transport::server::Dispatch;
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Role {
            Entry,
            Transit,
            Control,
            Terminal,
        }
        let service = self.clone();
        Arc::new(move || {
            let context = Arc::new(entry::ConnectionContext::default());
            let role = Mutex::new(None);
            let service = service.clone();
            let terminal = terminal.clone();
            Arc::new(move |path, registered| {
                let mut cap = gcoms_transport::decode_b64url(path).unwrap_or_default();
                let now = now_unix();
                let intro = service.gc2_introduction(now);
                let entry = bool::from(cap.as_slice().ct_eq(&intro.entry_cap));
                let transit = bool::from(cap.as_slice().ct_eq(&intro.transit_cap));
                let control = bool::from(cap.as_slice().ct_eq(&intro.reentry_cap));
                zeroize::Zeroize::zeroize(&mut cap);
                let requested = if entry {
                    Role::Entry
                } else if transit {
                    Role::Transit
                } else if control {
                    Role::Control
                } else {
                    let mut selected = role.lock().unwrap_or_else(|p| p.into_inner());
                    if selected.is_some_and(|role| role != Role::Terminal) {
                        return Dispatch::Rejected;
                    }
                    if registered {
                        *selected = Some(Role::Terminal);
                        return Dispatch::Pass;
                    }
                    if let Some(accepted) = terminal.as_ref().and_then(|handler| handler(path)) {
                        *selected = Some(Role::Terminal);
                        return Dispatch::Accepted(accepted);
                    }
                    // An unknown path neither promotes source admission nor
                    // commits the physical connection to a service role.
                    return Dispatch::Rejected;
                };
                // Possessing both capabilities cannot add unshaped transit
                // paths to a connection already bound as a protected entry.
                let mut selected = role.lock().unwrap_or_else(|p| p.into_inner());
                if selected.is_some_and(|role| role != requested || role == Role::Transit) {
                    return Dispatch::Rejected;
                }
                // A nested TLS connection extends exactly one middle target;
                // only the protected entry role multiplexes circuit opens.
                *selected = Some(requested);
                drop(selected);
                if control {
                    let service = service.clone();
                    let accepted: AcceptedDuplex = Box::new(move |body, respond| {
                        Box::pin(async move {
                            let _ = service.gc2_introductions(body, respond).await;
                        })
                    });
                    return Dispatch::Accepted(accepted);
                }
                let connect = service.gc2_target_connector();
                Dispatch::Accepted(if entry {
                    context.accept(intro.expires_at, connect)
                } else {
                    transit::accept(intro.expires_at, connect)
                })
            })
        })
    }

    pub fn address(&self) -> SocketAddr {
        *self.addr.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Change only the reachability candidate; service identity and capabilities
    /// survive a router lease renewal or address change.
    pub fn update_address(&self, address: SocketAddr) {
        let mut current = self.addr.lock().unwrap_or_else(|p| p.into_inner());
        if *current != address {
            *current = address;
            // Cached grants name the old endpoint. Existing queues remain owned;
            // subsequent provisioning returns a fresh grant at the new candidate.
            self.private
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .provisions
                .clear();
        }
    }

    pub fn active_circuits(&self) -> usize {
        self.policy.max_circuits - self.slots.available_permits()
    }

    pub fn configure_catalog_origins(&self, origins: Vec<String>) -> Result<()> {
        if origins.len() > 8 || origins.iter().any(|h| !crate::wire::valid_host(h)) {
            return Err("invalid catalog origin allowlist".into());
        }
        *self
            .catalog_origins
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = origins;
        Ok(())
    }

    pub fn handler(self: &Arc<Self>) -> DuplexHandler {
        let service = self.clone();
        Arc::new(move |path| {
            let mut cap = gcoms_transport::decode_b64url(path)?;
            let own = service.introduction(now_unix());
            let circuit = bool::from(cap.as_slice().ct_eq(&own.circuit_cap));
            let reentry = bool::from(cap.as_slice().ct_eq(&own.reentry_cap));
            zeroize::Zeroize::zeroize(&mut cap);
            if !circuit && !reentry {
                return None;
            }
            let service = service.clone();
            let permit = service.slots.clone().try_acquire_owned();
            Some(Box::new(move |body, mut respond| -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
                Box::pin(async move {
                    let Ok(_permit) = permit else {
                        let _ = carrier::respond(&mut respond, 2).await;
                        return;
                    };
                    if circuit {
                        let _ = service.circuit(body, respond, own.expires_at).await;
                    } else {
                        let _ = service.introductions(body, respond).await;
                    }
                })
            }) as AcceptedDuplex)
        })
    }

    async fn circuit(
        &self,
        body: h2::RecvStream,
        mut response: h2::server::SendResponse<bytes::Bytes>,
        expires_at: u64,
    ) -> Result<()> {
        let mut records = Records::new(body);
        let opened = tokio::time::timeout(Duration::from_secs(30), async {
            let record = records.next().await?;
            if record.kind != Kind::Open {
                return Err("expected carrier open".into());
            }
            let target = Target::decode(&record.payload)?;
            self.connect_target(target).await
        })
        .await;
        let io = match opened {
            Ok(Ok(io)) => io,
            _ => {
                let _ = carrier::respond(&mut response, 1).await;
                return Err("carrier target unavailable".into());
            }
        };
        let send = carrier::respond(&mut response, 0).await?;
        let remaining = Duration::from_secs(expires_at.saturating_sub(now_unix()));
        tokio::time::timeout(
            remaining.min(self.policy.carrier.lifetime),
            carrier::pump(io, send, records, self.policy.carrier),
        )
        .await
        .map_err(|_| "carrier lifetime exhausted")?
    }

    async fn connect_target(&self, target: Target) -> Result<BoxStream> {
        if self
            .policy
            .transit_ready
            .as_ref()
            .is_some_and(|ready| !ready.load(std::sync::atomic::Ordering::Acquire))
        {
            return Err("public transit has no current independent reachability proof".into());
        }
        let addrs = match target {
            Target::Relay { addr, service_id } => {
                if service_id == self.service_id
                    || addr.ip() == self.address().ip()
                    || !(self.policy.target_allowed)(addr)
                {
                    return Err("circuit target is not admitted".into());
                }
                vec![addr]
            }
            Target::Https { host, port } => {
                if port != 443
                    || !self
                        .catalog_origins
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .contains(&host)
                {
                    return Err("catalog origin is not admitted".into());
                }
                let addrs: Vec<_> = if let Some(resolve) = &self.policy.fixture_catalog_resolver {
                    resolve(&host)
                } else {
                    tokio::net::lookup_host((host.as_str(), port))
                        .await?
                        .take(17)
                        .collect()
                };
                if addrs.is_empty()
                    || addrs.len() > 16
                    || addrs.iter().any(|a| !(self.policy.target_allowed)(*a))
                {
                    return Err("catalog resolved to a prohibited address".into());
                }
                addrs
            }
        };
        for addr in addrs {
            if let Ok(Ok(stream)) = tokio::time::timeout(
                Duration::from_secs(10),
                tokio::net::TcpStream::connect(addr),
            )
            .await
            {
                stream.set_nodelay(true)?;
                return Ok(Box::new(stream));
            }
        }
        Err("circuit target did not connect".into())
    }

    async fn introductions(
        &self,
        body: h2::RecvStream,
        mut response: h2::server::SendResponse<bytes::Bytes>,
    ) -> Result<()> {
        let mut records = Records::new(body);
        let record = tokio::time::timeout(Duration::from_secs(30), records.next()).await??;
        match record.kind {
            Kind::Provision => return self.provision(&record.payload, response).await,
            Kind::Advertise => return self.advertise(&record.payload, response).await,
            _ => (),
        }
        if record.kind != Kind::Introduce || !record.payload.is_empty() {
            let _ = carrier::respond(&mut response, 1).await;
            return Err("invalid introduction request".into());
        }
        let now = now_unix();
        let mut candidates = self.directory.introductions();
        candidates.retain(|r| r.expires_at > now && r.service_id != self.service_id);
        candidates.shuffle(&mut rand::thread_rng());
        candidates.truncate(7);
        candidates.insert(0, self.introduction(now));
        let mut payload = Vec::with_capacity(1 + candidates.len() * RELAY_BYTES);
        payload.push(candidates.len() as u8);
        for relay in candidates {
            payload.extend_from_slice(&relay.encode()?);
        }
        let headers = http::Response::builder()
            .status(200)
            .header("content-type", "application/octet-stream")
            .body(())?;
        let mut send = response.send_response(headers, false)?;
        carrier::send_record(&mut send, Kind::Introductions, &payload, true).await
    }

    async fn provision(
        &self,
        payload: &[u8],
        mut response: h2::server::SendResponse<bytes::Bytes>,
    ) -> Result<()> {
        let id: [u8; 32] = payload.try_into()?;
        if id == [0; 32] {
            return Err("empty private request ID".into());
        }
        let reply = {
            let mut state = self.private.lock().unwrap_or_else(|p| p.into_inner());
            state
                .provisions
                .retain(|_, (at, _)| at.elapsed() < Duration::from_secs(120));
            if let Some((_, reply)) = state.provisions.get(&id) {
                reply.clone()
            } else {
                state.admit()?;
                if state.provisions.len() >= 128 {
                    return Err("provision retry cache full".into());
                }
                let provision = self
                    .policy
                    .provision
                    .as_ref()
                    .ok_or("inbox provisioning unavailable")?;
                let reply = Zeroizing::new(provision()?);
                if reply.is_empty() || reply.len() > carrier::MAX_PROVISION_BYTES {
                    return Err("private provision exceeds bounds".into());
                }
                state.provisions.insert(id, (Instant::now(), reply.clone()));
                reply
            }
        };
        let headers = http::Response::builder()
            .status(200)
            .header("content-type", "application/octet-stream")
            .body(())?;
        let mut send = response.send_response(headers, false)?;
        let mut offset = 0;
        while offset < reply.len() {
            let end = (offset + crate::wire::MAX_DATA - 4).min(reply.len());
            let mut part = Zeroizing::new(Vec::with_capacity(4 + end - offset));
            part.extend_from_slice(&(reply.len() as u32).to_be_bytes());
            part.extend_from_slice(&reply[offset..end]);
            carrier::send_record(&mut send, Kind::Provisioned, &part, end == reply.len()).await?;
            offset = end;
        }
        Ok(())
    }

    async fn advertise(
        &self,
        payload: &[u8],
        mut response: h2::server::SendResponse<bytes::Bytes>,
    ) -> Result<()> {
        let advertised = Relay::decode(payload)?;
        let now = now_unix();
        if advertised.conflicts(self.address(), self.service_id)
            || !(self.policy.target_allowed)(advertised.addr)
            || advertised.expires_at <= now
            || advertised.expires_at.saturating_sub(now) > crate::directory::MAX_ADVERTISEMENT_AGE
        {
            return Err("advertised service is not eligible".into());
        }
        let _probe = self
            .probes
            .try_acquire()
            .map_err(|_| "reachability probes busy")?;
        self.private
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .admit()?;
        // The originator's enclosing circuit provides no evidence of public
        // reachability. Authenticate the claimed independent listener ourselves.
        let refreshed = tokio::time::timeout(Duration::from_secs(20), async {
            let raw = tokio::net::TcpStream::connect(advertised.addr).await?;
            raw.set_nodelay(true)?;
            carrier::refresh(Box::new(raw), &advertised).await
        })
        .await
        .map_err(|_| "reachability probe timed out")??;
        let verified = refreshed
            .into_iter()
            .next()
            .ok_or("probe returned no service")?;
        if verified.addr != advertised.addr || verified.service_id != advertised.service_id {
            return Err("listener candidate changed during independent reachability probe".into());
        }
        self.directory.install(verified, now_unix())?;
        let headers = http::Response::builder()
            .status(200)
            .header("content-type", "application/octet-stream")
            .body(())?;
        let mut send = response.send_response(headers, false)?;
        carrier::send_record(&mut send, Kind::Advertised, &[0], true).await
    }
}

pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 168 || b == 0 && (c == 0 || c == 2)))
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && (b == 18 || b == 19 || b == 51 && c == 100))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            // Only globally routed unicast. Reject transition/documentation
            // ranges that could embed or redirect to a prohibited IPv4 address.
            (s[0] & 0xe000) == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

#[cfg(test)]
mod connectivity_tests {
    use super::*;

    #[tokio::test]
    async fn address_change_preserves_service_keys_and_unprobed_transit_is_refused() {
        let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let service = RelayService::new(
            "127.0.0.61:41000".parse().unwrap(),
            [5; 32],
            [6; 32],
            Arc::new(Directory::new()),
            ServicePolicy {
                transit_ready: Some(ready.clone()),
                target_allowed: Arc::new(|address| address.ip().is_loopback()),
                ..Default::default()
            },
        )
        .unwrap();
        let before = service.introduction(now_unix());
        let terminal = tokio::net::TcpListener::bind("127.0.0.62:0").await.unwrap();
        let target = Target::Relay {
            addr: terminal.local_addr().unwrap(),
            service_id: [7; 32],
        };
        assert!(service.connect_target(target.clone()).await.is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), terminal.accept())
                .await
                .is_err()
        );
        ready.store(true, std::sync::atomic::Ordering::Release);
        let stream = service.connect_target(target.clone()).await.unwrap();
        let accepted = terminal.accept().await.unwrap();
        drop((stream, accepted));
        ready.store(false, std::sync::atomic::Ordering::Release);
        service.update_address("127.0.0.63:42000".parse().unwrap());
        let after = service.introduction(now_unix());
        assert_ne!(before.addr, after.addr);
        assert_eq!(before.service_id, after.service_id);
        assert_eq!(before.reentry_cap, after.reentry_cap);
        assert_eq!(before.circuit_cap, after.circuit_cap);
        assert!(service.connect_target(target).await.is_err());
    }
}
