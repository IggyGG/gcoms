//! Temporary mappings for the exclusively held **transport** TCP listener.
//!
//! The caller must retain that listener through cleanup. Never pass the management
//! listener here. A gateway grant is not evidence of public reachability.
//! Wire references: RFC 6887 §7/11 (PCP), RFC 6886 §3 (NAT-PMP), and the UPnP
//! WANIPConnection:1/:2 service specifications. No wildcard/third-party mappings.
use quick_xml::{events::Event, Reader};
use rand::RngCore;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    time::{timeout, timeout_at, Instant},
};
use url::Url;

const MAX_XML: usize = 128 * 1024;
const MAX_LEASE: u64 = 7200;
const SERVICES: [&str; 3] = [
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];

#[derive(Clone, Debug)]
pub struct NatConfig {
    pub gateway: Option<Ipv4Addr>,
    pub requested_lifetime: Duration,
    pub request_timeout: Duration,
    pub discovery_timeout: Duration,
    pub operation_timeout: Duration,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            gateway: None,
            requested_lifetime: Duration::from_secs(1200),
            request_timeout: Duration::from_secs(2),
            discovery_timeout: Duration::from_secs(2),
            operation_timeout: Duration::from_secs(30),
        }
    }
}

impl NatConfig {
    fn validate(&self) -> Result<(), String> {
        if !(1..=MAX_LEASE).contains(&self.requested_lifetime.as_secs())
            || self.requested_lifetime.subsec_nanos() != 0
            || self.request_timeout.is_zero()
            || self.request_timeout > Duration::from_secs(30)
            || self.discovery_timeout.is_zero()
            || self.discovery_timeout > Duration::from_secs(10)
            || self.operation_timeout.is_zero()
            || self.operation_timeout > Duration::from_secs(120)
        {
            return Err("invalid finite NAT operation bounds".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Endpoints {
    gateway: SocketAddrV4,
    discovery: SocketAddrV4,
}

enum Protocol {
    Pcp { nonce: [u8; 12] },
    Pmp { epoch: u32, observed: Instant },
    Igd(Igd),
}

/// Not Clone: one owner renews/deletes this finite lease while holding the socket.
pub struct Mapping {
    local: SocketAddrV4,
    external: SocketAddrV4,
    lifetime: Duration,
    expires: Instant,
    config: NatConfig,
    endpoints: Endpoints,
    protocol: Protocol,
    removed: bool,
}

impl Mapping {
    pub async fn create(local: SocketAddrV4, config: &NatConfig) -> Result<Self, String> {
        config.validate()?;
        validate_local(local)?;
        let gateway = match config.gateway {
            Some(ip) => ip,
            None => discover_gateway().await?,
        };
        validate_ip(gateway)?;
        Self::create_at(
            local,
            config,
            Endpoints {
                gateway: SocketAddrV4::new(gateway, 5351),
                discovery: SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900),
            },
        )
        .await
    }

    async fn create_at(
        local: SocketAddrV4,
        config: &NatConfig,
        endpoints: Endpoints,
    ) -> Result<Self, String> {
        config.validate()?;
        validate_local(local)?;
        timeout(config.operation_timeout, async {
            let mut failures = Vec::new();
            let mut nonce = [0; 12];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let suggested = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, local.port());
            let requested = config.requested_lifetime.as_secs() as u32;
            let started = Instant::now();
            match pcp_map(
                local,
                endpoints.gateway,
                nonce,
                suggested,
                requested,
                config,
            )
            .await
            {
                Ok(grant) => {
                    return Self::from_grant(
                        local,
                        config,
                        endpoints,
                        Protocol::Pcp { nonce },
                        grant,
                        started,
                    )
                }
                Err(e) => failures.push(format!("PCP: {e}")),
            }
            let started = Instant::now();
            match pmp_create(local, endpoints.gateway, requested, config).await {
                Ok((grant, epoch)) => {
                    return Self::from_grant(
                        local,
                        config,
                        endpoints,
                        Protocol::Pmp {
                            epoch,
                            observed: started,
                        },
                        grant,
                        started,
                    )
                }
                Err(e) => failures.push(format!("NAT-PMP: {e}")),
            }
            let started = Instant::now();
            match Igd::create(local, endpoints, config).await {
                Ok((igd, grant)) => {
                    Self::from_grant(local, config, endpoints, Protocol::Igd(igd), grant, started)
                }
                Err(e) => {
                    failures.push(format!("UPnP IGD: {e}"));
                    Err(failures.join("; "))
                }
            }
        })
        .await
        .map_err(|_| {
            "NAT mapping operation deadline elapsed; any unconfirmed lease must expire naturally"
                .to_string()
        })?
    }

    fn from_grant(
        local: SocketAddrV4,
        config: &NatConfig,
        endpoints: Endpoints,
        protocol: Protocol,
        grant: Grant,
        started: Instant,
    ) -> Result<Self, String> {
        let expires = started + grant.lifetime;
        if expires <= Instant::now() {
            return Err("mapping grant expired before operation completed".into());
        }
        Ok(Self {
            local,
            external: grant.external,
            lifetime: grant.lifetime,
            expires,
            config: config.clone(),
            endpoints,
            protocol,
            removed: false,
        })
    }

    pub fn external_addr(&self) -> SocketAddrV4 {
        self.external
    }
    pub fn local_addr(&self) -> SocketAddrV4 {
        self.local
    }
    pub fn lifetime(&self) -> Duration {
        self.lifetime
    }
    /// Remaining time from the original grant request, never from response arrival.
    pub fn remaining_lifetime(&self) -> Duration {
        if self.removed {
            Duration::ZERO
        } else {
            self.expires.saturating_duration_since(Instant::now())
        }
    }

    pub async fn renew(&mut self) -> Result<(), String> {
        self.ensure_owned()?;
        let started = Instant::now();
        let original_expiry = self.expires;
        let requested = self.config.requested_lifetime.as_secs() as u32;
        let grant = timeout_at(
            original_expiry.min(started + self.config.operation_timeout),
            async {
                match &mut self.protocol {
                    Protocol::Pcp { nonce } => {
                        pcp_map(
                            self.local,
                            self.endpoints.gateway,
                            *nonce,
                            self.external,
                            requested,
                            &self.config,
                        )
                        .await
                    }
                    Protocol::Pmp { epoch, observed } => {
                        let (address, current_epoch) =
                            pmp_address(self.local, self.endpoints.gateway, &self.config).await?;
                        check_epoch(*epoch, *observed, current_epoch)?;
                        if Instant::now() >= original_expiry {
                            return Err("mapping expired during ownership check".into());
                        }
                        let (grant, new_epoch) = pmp_map(
                            self.local,
                            self.endpoints.gateway,
                            address,
                            self.external.port(),
                            requested,
                            &self.config,
                        )
                        .await?;
                        check_epoch(current_epoch, started, new_epoch)?;
                        *epoch = new_epoch;
                        *observed = started;
                        Ok(grant)
                    }
                    Protocol::Igd(igd) => {
                        igd.renew(
                            self.local,
                            self.external.port(),
                            &self.config,
                            original_expiry,
                        )
                        .await
                    }
                }
            },
        )
        .await
        .map_err(|_| "NAT renewal deadline elapsed".to_string())??;
        self.external = grant.external;
        self.lifetime = grant.lifetime;
        self.expires = started + grant.lifetime;
        if self.expires <= Instant::now() {
            return Err("renewed grant already expired".into());
        }
        Ok(())
    }

    pub async fn cleanup(&mut self) -> Result<(), String> {
        if self.removed {
            return Ok(());
        }
        self.ensure_owned()?;
        timeout_at(
            self.expires
                .min(Instant::now() + self.config.operation_timeout),
            async {
                match &self.protocol {
                    Protocol::Pcp { nonce } => {
                        pcp_map(
                            self.local,
                            self.endpoints.gateway,
                            *nonce,
                            self.external,
                            0,
                            &self.config,
                        )
                        .await?;
                    }
                    Protocol::Pmp { epoch, observed } => {
                        let (address, current_epoch) =
                            pmp_address(self.local, self.endpoints.gateway, &self.config).await?;
                        check_epoch(*epoch, *observed, current_epoch)?;
                        if address != *self.external.ip() {
                            return Err("NAT-PMP external address changed; deletion refused".into());
                        }
                        // RFC6886 requires suggested external port zero for deletion.
                        // Internal port is ALWAYS this retained, nonzero listener.
                        self.ensure_owned()?;
                        pmp_map(
                            self.local,
                            self.endpoints.gateway,
                            address,
                            0,
                            0,
                            &self.config,
                        )
                        .await?;
                    }
                    Protocol::Igd(igd) => {
                        igd.owned_entry(self.local, self.external.port()).await?;
                        self.ensure_owned()?;
                        igd.soap("DeletePortMapping", &mapping_key(self.external.port()))
                            .await?;
                    }
                }
                Ok::<_, String>(())
            },
        )
        .await
        .map_err(|_| "NAT cleanup deadline elapsed; lease retained until expiry".to_string())??;
        self.removed = true;
        Ok(())
    }

    fn ensure_owned(&self) -> Result<(), String> {
        if self.removed || Instant::now() >= self.expires {
            Err("mapping removed/expired; refusing to alter a possibly reassigned mapping".into())
        } else {
            Ok(())
        }
    }
}

struct Grant {
    external: SocketAddrV4,
    lifetime: Duration,
}

fn grant(ip: Ipv4Addr, port: u16, seconds: u32, deleting: bool) -> Result<Grant, String> {
    if deleting {
        if seconds != 0 {
            return Err("gateway did not confirm lease deletion".into());
        }
    } else {
        validate_ip(ip)?;
        if port == 0 || seconds == 0 || u64::from(seconds) > MAX_LEASE {
            return Err("gateway returned invalid/permanent/excessive mapping grant".into());
        }
    }
    Ok(Grant {
        external: SocketAddrV4::new(ip, port),
        lifetime: Duration::from_secs(seconds.into()),
    })
}

fn validate_ip(ip: Ipv4Addr) -> Result<(), String> {
    if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
        Err("unusable IPv4 address".into())
    } else {
        Ok(())
    }
}
fn validate_local(local: SocketAddrV4) -> Result<(), String> {
    validate_ip(*local.ip())?;
    if local.port() == 0 {
        return Err("mapping requires the bound nonzero transport port".into());
    }
    Ok(())
}
fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

// A connected UDP socket binds source identity and ignores other gateway senders.
// Retransmissions reuse EXACT bytes/nonces. Both time and datagram count are bounded.
async fn exchange(
    local: Ipv4Addr,
    gateway: SocketAddrV4,
    request: &[u8],
    config: &NatConfig,
    initial_retry: Duration,
    accept: impl Fn(&[u8]) -> bool,
) -> Result<Vec<u8>, String> {
    let socket = UdpSocket::bind(SocketAddrV4::new(local, 0))
        .await
        .map_err(|e| e.to_string())?;
    socket.connect(gateway).await.map_err(|e| e.to_string())?;
    let end = Instant::now() + config.request_timeout;
    let mut delay = initial_retry;
    let mut buf = [0; 1101];
    for _ in 0..4 {
        socket.send(request).await.map_err(|e| e.to_string())?;
        let retry_at = (Instant::now() + delay).min(end);
        for _ in 0..16 {
            match timeout_at(retry_at, socket.recv(&mut buf)).await {
                Ok(Ok(n)) if n <= 1100 && accept(&buf[..n]) => return Ok(buf[..n].to_vec()),
                Ok(Ok(_)) => (),
                Ok(Err(e)) => return Err(e.to_string()),
                Err(_) => break,
            }
        }
        if Instant::now() >= end {
            break;
        }
        delay *= 2;
    }
    Err("gateway response timeout or unmatched response".into())
}

async fn pcp_map(
    local: SocketAddrV4,
    gateway: SocketAddrV4,
    nonce: [u8; 12],
    suggested: SocketAddrV4,
    seconds: u32,
    config: &NatConfig,
) -> Result<Grant, String> {
    let mut request = [0; 60];
    request[0] = 2;
    request[1] = 1;
    request[4..8].copy_from_slice(&seconds.to_be_bytes());
    request[8..24].copy_from_slice(&local.ip().to_ipv6_mapped().octets());
    request[24..36].copy_from_slice(&nonce);
    request[36] = 6;
    request[40..42].copy_from_slice(&local.port().to_be_bytes());
    request[42..44].copy_from_slice(&suggested.port().to_be_bytes());
    request[44..60].copy_from_slice(&suggested.ip().to_ipv6_mapped().octets());
    let response = exchange(
        *local.ip(),
        gateway,
        &request,
        config,
        Duration::from_secs(3),
        |b| {
            b.len() >= 24
                && b[0] == 2
                && b[1] == 129
                && (b[3] != 0
                    || (b.len() >= 60
                        && b[24..36] == nonce
                        && b[36] == 6
                        && u16_at(b, 40) == local.port()))
        },
    )
    .await?;
    if response[3] != 0 {
        return Err(format!("MAP refused ({})", response[3]));
    }
    // No options requested. Ignore only well-framed optional response options.
    let mut offset = 60;
    while offset < response.len() {
        if response.len() - offset < 4 || response[offset] < 128 {
            return Err("unsupported/malformed PCP response option".into());
        }
        offset += 4 + usize::from(u16_at(&response, offset + 2)).div_ceil(4) * 4;
        if offset > response.len() {
            return Err("truncated PCP response option".into());
        }
    }
    let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&response[44..60]).unwrap())
        .to_ipv4_mapped()
        .ok_or("PCP returned a non-IPv4 mapping")?;
    grant(
        ip,
        u16_at(&response, 42),
        u32_at(&response, 4),
        seconds == 0,
    )
}

async fn pmp_address(
    local: SocketAddrV4,
    gateway: SocketAddrV4,
    config: &NatConfig,
) -> Result<(Ipv4Addr, u32), String> {
    let b = exchange(
        *local.ip(),
        gateway,
        &[0, 0],
        config,
        Duration::from_millis(250),
        |b| b.len() == 12 && b[0] == 0 && b[1] == 128,
    )
    .await?;
    if u16_at(&b, 2) != 0 {
        return Err(format!("external address refused ({})", u16_at(&b, 2)));
    }
    let ip = Ipv4Addr::new(b[8], b[9], b[10], b[11]);
    validate_ip(ip)?;
    Ok((ip, u32_at(&b, 4)))
}
async fn pmp_map(
    local: SocketAddrV4,
    gateway: SocketAddrV4,
    external: Ipv4Addr,
    suggested: u16,
    seconds: u32,
    config: &NatConfig,
) -> Result<(Grant, u32), String> {
    let mut request = [0; 12];
    request[1] = 2;
    request[4..6].copy_from_slice(&local.port().to_be_bytes());
    request[6..8].copy_from_slice(&suggested.to_be_bytes());
    request[8..12].copy_from_slice(&seconds.to_be_bytes());
    let b = exchange(
        *local.ip(),
        gateway,
        &request,
        config,
        Duration::from_millis(250),
        |b| b.len() == 16 && b[0] == 0 && b[1] == 130 && u16_at(b, 8) == local.port(),
    )
    .await?;
    if u16_at(&b, 2) != 0 {
        return Err(format!("TCP mapping refused ({})", u16_at(&b, 2)));
    }
    if seconds == 0 && u16_at(&b, 10) != 0 {
        return Err("NAT-PMP deletion returned nonzero external port".into());
    }
    Ok((
        grant(external, u16_at(&b, 10), u32_at(&b, 12), seconds == 0)?,
        u32_at(&b, 4),
    ))
}
async fn pmp_create(
    local: SocketAddrV4,
    gateway: SocketAddrV4,
    seconds: u32,
    config: &NatConfig,
) -> Result<(Grant, u32), String> {
    let observed = Instant::now();
    let (ip, epoch) = pmp_address(local, gateway, config).await?;
    let (grant, new_epoch) = pmp_map(local, gateway, ip, local.port(), seconds, config).await?;
    check_epoch(epoch, observed, new_epoch)?;
    Ok((grant, new_epoch))
}
fn check_epoch(previous: u32, observed: Instant, current: u32) -> Result<(), String> {
    let expected = u64::from(previous) + observed.elapsed().as_secs() * 7 / 8;
    if u64::from(current) + 2 < expected {
        Err("NAT-PMP gateway lost mapping state; old ownership unavailable".into())
    } else {
        Ok(())
    }
}

struct Igd {
    client: reqwest::Client,
    control: Url,
    service: String,
    owner: String,
}
struct SoapError {
    code: Option<u16>,
    message: String,
}
impl From<SoapError> for String {
    fn from(e: SoapError) -> Self {
        e.message
    }
}
type Fields = BTreeMap<String, String>;

impl Igd {
    async fn create(
        local: SocketAddrV4,
        endpoints: Endpoints,
        config: &NatConfig,
    ) -> Result<(Self, Grant), String> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.request_timeout)
            .local_address(IpAddr::V4(*local.ip()))
            .build()
            .map_err(|e| e.to_string())?;
        let location = discover_igd(local, endpoints, config).await?;
        let body = http_body(
            client
                .get(location.clone())
                .send()
                .await
                .map_err(|e| e.to_string())?,
            true,
        )
        .await?;
        let (service, control) = igd_service(&body, &location, *endpoints.gateway.ip())?;
        let mut random = [0; 16];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let owner = format!(
            "ghost-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let igd = Self {
            client,
            control,
            service,
            owner,
        };
        let external = igd.external_ip().await?;
        let suggested = 49152 + (rand::rngs::OsRng.next_u32() % 16384) as u16;
        // Never overwrite a pre-existing mapping, even one targeting this port.
        match igd
            .soap("GetSpecificPortMappingEntry", &mapping_key(suggested))
            .await
        {
            Err(SoapError {
                code: Some(714), ..
            }) => (),
            Err(e) => return Err(e.into()),
            Ok(_) => return Err("UPnP candidate port already mapped; refusing adoption".into()),
        }
        let any = igd.service.ends_with(":2");
        let response = igd
            .soap(
                if any {
                    "AddAnyPortMapping"
                } else {
                    "AddPortMapping"
                },
                &igd.arguments(local, suggested, config),
            )
            .await?;
        let port = if any {
            field(&response, "NewReservedPort")?
                .parse::<u16>()
                .map_err(|_| "invalid IGD assigned port")?
        } else {
            suggested
        };
        if port == 0 {
            return Err("IGD returned zero external port".into());
        }
        let seconds = igd.finite_entry(local, port).await?;
        Ok((igd, grant(external, port, seconds, false)?))
    }

    fn arguments(&self, local: SocketAddrV4, port: u16, config: &NatConfig) -> String {
        format!("{}<NewInternalPort>{}</NewInternalPort><NewInternalClient>{}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>{}</NewPortMappingDescription><NewLeaseDuration>{}</NewLeaseDuration>", mapping_key(port),local.port(),local.ip(),self.owner,config.requested_lifetime.as_secs())
    }
    async fn external_ip(&self) -> Result<Ipv4Addr, String> {
        let fields = self.soap("GetExternalIPAddress", "").await?;
        let ip = field(&fields, "NewExternalIPAddress")?
            .parse()
            .map_err(|_| "invalid IGD external IP")?;
        validate_ip(ip)?;
        Ok(ip)
    }
    async fn owned_entry(&self, local: SocketAddrV4, port: u16) -> Result<u32, String> {
        let fields = self
            .soap("GetSpecificPortMappingEntry", &mapping_key(port))
            .await?;
        if field(&fields, "NewInternalClient")?
            .parse::<Ipv4Addr>()
            .ok()
            != Some(*local.ip())
            || field(&fields, "NewInternalPort")?.parse::<u16>().ok() != Some(local.port())
            || field(&fields, "NewPortMappingDescription")? != self.owner
            || !matches!(field(&fields, "NewEnabled")?, "1" | "true")
        {
            return Err("UPnP mapping ownership changed; refusing renewal/deletion".into());
        }
        let seconds = field(&fields, "NewLeaseDuration")?
            .parse::<u32>()
            .map_err(|_| "invalid IGD lease")?;
        Ok(seconds)
    }
    async fn finite_entry(&self, local: SocketAddrV4, port: u16) -> Result<u32, String> {
        // The description, internal client, protocol key and port were verified
        // BEFORE deciding whether this grant can be published. A router that
        // ignores our finite duration must not leave our own permanent pinhole.
        let seconds = self.owned_entry(local, port).await?;
        if seconds == 0 || u64::from(seconds) > MAX_LEASE {
            let cleanup = self.soap("DeletePortMapping", &mapping_key(port)).await;
            return Err(format!(
                "UPnP lease is permanent/invalid; owned grant cleanup {}",
                match cleanup {
                    Ok(_) => "confirmed".to_string(),
                    Err(e) => format!("unconfirmed: {}", e.message),
                }
            ));
        }
        Ok(seconds)
    }
    async fn renew(
        &self,
        local: SocketAddrV4,
        port: u16,
        config: &NatConfig,
        expires: Instant,
    ) -> Result<Grant, String> {
        self.finite_entry(local, port).await?;
        if Instant::now() >= expires {
            return Err("UPnP mapping expired during ownership check".into());
        }
        self.soap("AddPortMapping", &self.arguments(local, port, config))
            .await?;
        let seconds = self.finite_entry(local, port).await?;
        grant(self.external_ip().await?, port, seconds, false)
    }
    async fn soap(&self, action: &str, arguments: &str) -> Result<Fields, SoapError> {
        let request = format!("<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{}\">{arguments}</u:{action}></s:Body></s:Envelope>",self.service);
        let response = self
            .client
            .post(self.control.clone())
            .header("Content-Type", "text/xml; charset=\"utf-8\"")
            .header("SOAPAction", format!("\"{}#{action}\"", self.service))
            .body(request)
            .send()
            .await
            .map_err(|e| SoapError {
                code: None,
                message: e.to_string(),
            })?;
        let success = response.status().is_success();
        let body = http_body(response, false)
            .await
            .map_err(|message| SoapError {
                code: None,
                message,
            })?;
        let fields = xml_fields(&body).map_err(|message| SoapError {
            code: None,
            message,
        })?;
        if !success || fields.contains_key("errorCode") {
            let code = fields.get("errorCode").and_then(|v| v.parse().ok());
            return Err(SoapError {
                code,
                message: format!("IGD {action} refused ({code:?})"),
            });
        }
        Ok(fields)
    }
}

fn mapping_key(port: u16) -> String {
    format!("<NewRemoteHost></NewRemoteHost><NewExternalPort>{port}</NewExternalPort><NewProtocol>TCP</NewProtocol>")
}
fn field<'a>(fields: &'a Fields, name: &str) -> Result<&'a str, String> {
    fields
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("missing IGD field {name}"))
}

async fn http_body(
    mut response: reqwest::Response,
    require_success: bool,
) -> Result<Vec<u8>, String> {
    if (require_success && !response.status().is_success()) || response.status().is_redirection() {
        return Err("IGD HTTP request refused/redirected".into());
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_XML as u64)
    {
        return Err("IGD HTTP body too large".into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if body.len() + chunk.len() > MAX_XML {
            return Err("IGD HTTP body too large".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn pinned_url(value: &str, base: Option<&Url>, gateway: Ipv4Addr) -> Result<Url, String> {
    let url = match base {
        Some(base) => base.join(value),
        None => Url::parse(value),
    }
    .map_err(|_| "invalid IGD URL")?;
    if url.scheme() != "http"
        || url.host() != Some(url::Host::Ipv4(gateway))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() == Some(0)
    {
        return Err("IGD URL must stay on selected gateway with no credentials/redirects".into());
    }
    Ok(url)
}

async fn discover_igd(
    local: SocketAddrV4,
    endpoints: Endpoints,
    config: &NatConfig,
) -> Result<Url, String> {
    let socket = UdpSocket::bind(SocketAddrV4::new(*local.ip(), 0))
        .await
        .map_err(|e| e.to_string())?;
    socket.set_multicast_ttl_v4(2).map_err(|e| e.to_string())?;
    for service in SERVICES {
        let request=format!("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {service}\r\n\r\n");
        socket
            .send_to(request.as_bytes(), endpoints.discovery)
            .await
            .map_err(|e| e.to_string())?;
    }
    let end = Instant::now() + config.discovery_timeout;
    let mut buf = [0; 4097];
    for _ in 0..32 {
        let (n, source) = timeout_at(end, socket.recv_from(&mut buf))
            .await
            .map_err(|_| "IGD discovery timeout")?
            .map_err(|e| e.to_string())?;
        if n > 4096 || source.ip() != IpAddr::V4(*endpoints.gateway.ip()) {
            continue;
        }
        let Ok(response) = std::str::from_utf8(&buf[..n]) else {
            continue;
        };
        let mut lines = response.lines();
        if !lines.next().is_some_and(|s| s.starts_with("HTTP/1.1 200 ")) {
            continue;
        }
        let locations: Vec<_> = lines
            .filter_map(|line| line.split_once(':'))
            .filter(|(k, _)| k.eq_ignore_ascii_case("location"))
            .collect();
        if let [(_, location)] = locations.as_slice() {
            if let Ok(url) = pinned_url(location.trim(), None, *endpoints.gateway.ip()) {
                return Ok(url);
            }
        }
    }
    Err("IGD discovery exhausted bounded responses".into())
}

// Use a real XML parser; bound depth/events/body and reject DTD/entity expansion.
// Leaves retain their path so descriptor service fields cannot mix across devices.
fn xml_leaves(body: &[u8]) -> Result<Vec<(Vec<String>, String)>, String> {
    if body.len() > MAX_XML {
        return Err("XML too large".into());
    }
    let mut reader = Reader::from_reader(body);
    let mut stack: Vec<String> = Vec::new();
    let mut texts: Vec<String> = Vec::new();
    let mut leaves = Vec::new();
    let mut roots = 0;
    for _ in 0..16384 {
        match reader.read_event().map_err(|e| e.to_string())? {
            Event::Start(e) => {
                if stack.is_empty() {
                    roots += 1;
                }
                if roots > 1 {
                    return Err("multiple XML roots".into());
                }
                stack.push(
                    String::from_utf8(e.local_name().as_ref().to_vec())
                        .map_err(|_| "invalid XML name")?,
                );
                texts.push(String::new());
                if stack.len() > 32 {
                    return Err("XML nesting too deep".into());
                }
            }
            Event::End(_) => {
                let text = texts.pop().ok_or("unbalanced XML")?;
                if !text.trim().is_empty() {
                    leaves.push((stack.clone(), text.trim().to_string()));
                }
                stack.pop().ok_or("unbalanced XML")?;
            }
            Event::Text(e) => {
                let decoded = e.decode().map_err(|e| e.to_string())?;
                if let Some(text) = texts.last_mut() {
                    text.push_str(&decoded);
                } else if !decoded.trim().is_empty() {
                    return Err("XML text outside root".into());
                }
            }
            Event::CData(e) => texts
                .last_mut()
                .ok_or("XML CDATA outside element")?
                .push_str(&e.decode().map_err(|e| e.to_string())?),
            Event::GeneralRef(e) => {
                let name = e.decode().map_err(|e| e.to_string())?;
                let value = match name.as_ref() {
                    "amp" => '&',
                    "lt" => '<',
                    "gt" => '>',
                    "apos" => '\'',
                    "quot" => '"',
                    _ => e
                        .resolve_char_ref()
                        .map_err(|e| e.to_string())?
                        .ok_or("unknown XML entity refused")?,
                };
                if !matches!(value, '\t' | '\n' | '\r')
                    && (value < '\u{20}' || matches!(value, '\u{fffe}' | '\u{ffff}'))
                {
                    return Err("invalid XML character reference".into());
                }
                texts
                    .last_mut()
                    .ok_or("XML reference outside element")?
                    .push(value);
            }
            Event::DocType(_) => return Err("XML DTD refused".into()),
            Event::Empty(_) => {
                if stack.is_empty() {
                    roots += 1;
                    if roots > 1 {
                        return Err("multiple XML roots".into());
                    }
                }
            }
            Event::Eof => {
                return if stack.is_empty() && roots == 1 {
                    Ok(leaves)
                } else {
                    Err("incomplete XML".into())
                }
            }
            _ => (),
        }
    }
    Err("XML event bound exceeded".into())
}
fn xml_fields(body: &[u8]) -> Result<Fields, String> {
    let mut fields = Fields::new();
    for (path, value) in xml_leaves(body)? {
        let name = path.last().ok_or("XML text outside element")?;
        if fields.insert(name.clone(), value).is_some() {
            return Err(format!("duplicate XML field {name}"));
        }
    }
    Ok(fields)
}
fn igd_service(body: &[u8], location: &Url, gateway: Ipv4Addr) -> Result<(String, Url), String> {
    // Parse individual service elements separately, not a document-wide field map.
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut base = location.clone();
    let mut services = Vec::new();
    for _ in 0..16384 {
        match reader.read_event().map_err(|e| e.to_string())? {
            Event::Start(e) if e.local_name().as_ref() == b"URLBase" => {
                let text = reader.read_text(e.name()).map_err(|e| e.to_string())?;
                let text = text.decode().map_err(|e| e.to_string())?;
                if !text.trim().is_empty() {
                    base = pinned_url(text.trim(), Some(location), gateway)?;
                }
            }
            Event::Start(e) if e.local_name().as_ref() == b"service" => {
                let raw = reader.read_text(e.name()).map_err(|e| e.to_string())?;
                let raw = raw.decode().map_err(|e| e.to_string())?;
                let fields = xml_fields(format!("<service>{raw}</service>").as_bytes())?;
                if let (Some(service), Some(control)) =
                    (fields.get("serviceType"), fields.get("controlURL"))
                {
                    if SERVICES.contains(&service.as_str()) {
                        services.push((service.clone(), control.clone()));
                    }
                }
            }
            Event::DocType(_) => return Err("XML DTD refused".into()),
            Event::Eof => {
                // Validate full document structure/depth too, including ignored devices.
                xml_leaves(body)?;
                services.sort_by_key(|(s, _)| SERVICES.iter().position(|v| v == s).unwrap_or(3));
                let (service, control) = services
                    .into_iter()
                    .next()
                    .ok_or("no supported IGD connection service")?;
                return Ok((service, pinned_url(&control, Some(&base), gateway)?));
            }
            _ => (),
        }
    }
    Err("IGD descriptor event bound exceeded".into())
}

/// Resolve an automatic IPv4 wildcard listener to its default-route LAN address.
/// UDP connect only selects the local route; it sends no packet or router request.
pub async fn resolve_local(bound: SocketAddr) -> Result<SocketAddrV4, String> {
    let SocketAddr::V4(bound) = bound else {
        return Err("IPv4 NAT mapping unavailable for IPv6 listener".into());
    };
    if !bound.ip().is_unspecified() {
        validate_local(bound)?;
        return Ok(bound);
    }
    if bound.port() == 0 {
        return Err("transport listener has no assigned port".into());
    }
    let gateway = discover_gateway().await?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|e| e.to_string())?;
    socket
        .connect((gateway, 5351))
        .await
        .map_err(|e| e.to_string())?;
    let SocketAddr::V4(address) = socket.local_addr().map_err(|e| e.to_string())? else {
        return Err("no IPv4 source route".into());
    };
    validate_ip(*address.ip())?;
    Ok(SocketAddrV4::new(*address.ip(), bound.port()))
}

async fn discover_gateway() -> Result<Ipv4Addr, String> {
    tokio::task::spawn_blocking(default_gateway)
        .await
        .map_err(|e| e.to_string())?
}

#[cfg(target_os = "linux")]
fn default_gateway() -> Result<Ipv4Addr, String> {
    parse_linux_routes(&std::fs::read_to_string("/proc/net/route").map_err(|e| e.to_string())?)
}
#[cfg(any(target_os = "linux", test))]
fn parse_linux_routes(text: &str) -> Result<Ipv4Addr, String> {
    let mut candidates = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
            continue;
        }
        let (Ok(gateway), Ok(flags), Ok(metric)) = (
            u32::from_str_radix(fields[2], 16),
            u32::from_str_radix(fields[3], 16),
            fields[6].parse::<u32>(),
        ) else {
            continue;
        };
        let ip = Ipv4Addr::from(gateway.to_le_bytes());
        if flags & 3 == 3 && validate_ip(ip).is_ok() {
            candidates.push((metric, ip));
        }
    }
    candidates.sort_unstable();
    candidates
        .first()
        .map(|(_, ip)| *ip)
        .ok_or_else(|| "no IPv4 default gateway; set NatConfig.gateway".into())
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn default_gateway() -> Result<Ipv4Addr, String> {
    // Read-only platform route command with owned child, bounded output and reap.
    use std::{
        io::Read,
        process::{Command, Stdio},
        thread,
        time::Instant as StdInstant,
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut c = Command::new("/sbin/route");
        c.args(["-n", "get", "default"]);
        c
    };
    #[cfg(target_os = "windows")]
    let mut command = {
        let root = std::env::var_os("SystemRoot").ok_or("SystemRoot unavailable")?;
        let mut c = Command::new(std::path::PathBuf::from(root).join("System32/route.exe"));
        c.args(["print", "-4"]);
        c
    };
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let pipe = child.stdout.take().ok_or("route stdout unavailable")?;
    let reader = thread::spawn(move || {
        let mut body = Vec::new();
        pipe.take(64 * 1024 + 1)
            .read_to_end(&mut body)
            .map(|_| body)
    });
    let end = StdInstant::now() + Duration::from_secs(2);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if StdInstant::now() < end => thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break Err("default route query failed/timed out");
            }
        }
    };
    let bytes = reader
        .join()
        .map_err(|_| "route reader failed")?
        .map_err(|e| e.to_string())?;
    if !status?.success() || bytes.len() > 64 * 1024 {
        return Err("default route query refused/oversized".into());
    }
    let text = String::from_utf8(bytes).map_err(|_| "invalid route output")?;
    parse_platform_routes(&text)
}
#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn parse_platform_routes(text: &str) -> Result<Ipv4Addr, String> {
    let mut candidates = Vec::new();
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() == 2 && fields[0] == "gateway:" {
            if let Ok(ip) = fields[1].parse::<Ipv4Addr>() {
                validate_ip(ip)?;
                return Ok(ip);
            }
        }
        if fields.len() >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
            if let (Ok(ip), Ok(metric)) = (fields[2].parse::<Ipv4Addr>(), fields[4].parse::<u32>())
            {
                if validate_ip(ip).is_ok() {
                    candidates.push((metric, ip));
                }
            }
        }
    }
    candidates.sort_unstable();
    candidates
        .first()
        .map(|(_, ip)| *ip)
        .ok_or_else(|| "no IPv4 default gateway; set NatConfig.gateway".into())
}
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn default_gateway() -> Result<Ipv4Addr, String> {
    Err("gateway discovery unsupported; set NatConfig.gateway".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    fn config() -> NatConfig {
        NatConfig {
            gateway: Some(Ipv4Addr::LOCALHOST),
            request_timeout: Duration::from_millis(200),
            discovery_timeout: Duration::from_millis(300),
            operation_timeout: Duration::from_secs(3),
            ..NatConfig::default()
        }
    }
    fn local() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4433)
    }
    fn external() -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, 47)
    }
    fn addr(socket: &UdpSocket) -> SocketAddrV4 {
        let SocketAddr::V4(a) = socket.local_addr().unwrap() else {
            panic!()
        };
        a
    }
    fn pcp_response(request: &[u8], port: u16, seconds: u32) -> Vec<u8> {
        assert_eq!(request.len(), 60);
        assert_eq!(request[0..2], [2, 1]);
        assert_eq!(request[36], 6);
        assert_eq!(u16_at(request, 40), 4433);
        assert_eq!(
            &request[8..24],
            &Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets()
        );
        let mut b = request.to_vec();
        b[1] = 129;
        b[3] = 0;
        b[4..8].copy_from_slice(&seconds.to_be_bytes());
        b[8..24].fill(0);
        b[42..44].copy_from_slice(&port.to_be_bytes());
        b[44..60].copy_from_slice(&external().to_ipv6_mapped().octets());
        b
    }
    fn pmp_response(request: &[u8], epoch: u32, port: u16, seconds: u32) -> Vec<u8> {
        assert_eq!(request[0], 0);
        let mut b = vec![0; if request[1] == 0 { 12 } else { 16 }];
        b[1] = request[1] + 128;
        b[4..8].copy_from_slice(&epoch.to_be_bytes());
        if request[1] == 0 {
            b[8..12].copy_from_slice(&external().octets());
        } else {
            assert_eq!(request[1], 2);
            assert_eq!(u16_at(request, 4), 4433);
            b[8..10].copy_from_slice(&request[4..6]);
            b[10..12].copy_from_slice(&port.to_be_bytes());
            b[12..16].copy_from_slice(&seconds.to_be_bytes());
        }
        b
    }

    #[tokio::test]
    async fn pcp_actual_grants_nonce_renewal_and_exact_cleanup() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let endpoints = Endpoints {
            gateway: addr(&server),
            discovery: addr(&server),
        };
        let task = tokio::spawn(async move {
            let mut buf = [0; 128];
            let mut nonce = None;
            for i in 0..3 {
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                let req = &buf[..n];
                if let Some(nonce) = nonce {
                    assert_eq!(req[24..36], nonce);
                } else {
                    nonce = Some(<[u8; 12]>::try_from(&req[24..36]).unwrap());
                }
                assert_eq!(u32_at(req, 4), if i == 2 { 0 } else { 1200 });
                assert_eq!(u16_at(req, 42), [4433, 50001, 50002][i]);
                let response =
                    pcp_response(req, if i == 0 { 50001 } else { 50002 }, [120, 80, 0][i]);
                if i == 0 {
                    let mut wrong = response.clone();
                    wrong[24] ^= 1;
                    server.send_to(&wrong, peer).await.unwrap();
                }
                server.send_to(&response, peer).await.unwrap();
            }
        });
        let mut mapping = Mapping::create_at(local(), &config(), endpoints)
            .await
            .unwrap();
        assert_eq!(
            mapping.external_addr(),
            SocketAddrV4::new(external(), 50001)
        );
        assert_eq!(mapping.lifetime(), Duration::from_secs(120));
        mapping.renew().await.unwrap();
        assert_eq!(mapping.external_addr().port(), 50002);
        assert_eq!(mapping.lifetime(), Duration::from_secs(80));
        mapping.cleanup().await.unwrap();
        mapping.cleanup().await.unwrap();
        assert!(mapping.renew().await.is_err());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn nat_pmp_fallback_preserves_assigned_tuple_and_finite_lifetime() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let endpoints = Endpoints {
            gateway: addr(&server),
            discovery: addr(&server),
        };
        let task = tokio::spawn(async move {
            let mut buf = [0; 128];
            for i in 0..7 {
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                let req = &buf[..n];
                let response = if i == 0 {
                    let mut b = pcp_response(req, 0, 0);
                    b[3] = 1;
                    b
                } else {
                    if [2, 4, 6].contains(&i) {
                        assert_eq!(
                            u16_at(req, 6),
                            if i == 2 {
                                4433
                            } else if i == 4 {
                                50011
                            } else {
                                0
                            }
                        );
                        assert_eq!(u32_at(req, 8), if i == 6 { 0 } else { 1200 });
                    }
                    pmp_response(
                        req,
                        100 + i as u32,
                        if i == 6 {
                            0
                        } else if i == 4 {
                            50012
                        } else {
                            50011
                        },
                        if i == 6 {
                            0
                        } else if i == 4 {
                            100
                        } else {
                            180
                        },
                    )
                };
                server.send_to(&response, peer).await.unwrap();
            }
        });
        let mut mapping = Mapping::create_at(local(), &config(), endpoints)
            .await
            .unwrap();
        assert!(matches!(mapping.protocol, Protocol::Pmp { .. }));
        assert_eq!(mapping.external_addr().port(), 50011);
        assert_eq!(mapping.lifetime(), Duration::from_secs(180));
        mapping.renew().await.unwrap();
        assert_eq!(mapping.external_addr().port(), 50012);
        assert_eq!(mapping.lifetime(), Duration::from_secs(100));
        mapping.cleanup().await.unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn nat_pmp_gateway_reset_refuses_delete_without_sending_delete() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let endpoints = Endpoints {
            gateway: addr(&server),
            discovery: addr(&server),
        };
        let mut mapping = Mapping::from_grant(
            local(),
            &config(),
            endpoints,
            Protocol::Pmp {
                epoch: 500,
                observed: Instant::now(),
            },
            grant(external(), 50012, 120, false).unwrap(),
            Instant::now(),
        )
        .unwrap();
        let task = tokio::spawn(async move {
            let mut buf = [0; 128];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], &[0, 0]);
            server
                .send_to(&pmp_response(&buf[..n], 1, 0, 0), peer)
                .await
                .unwrap();
            assert!(
                timeout(Duration::from_millis(100), server.recv_from(&mut buf))
                    .await
                    .is_err()
            );
        });
        assert!(mapping
            .cleanup()
            .await
            .unwrap_err()
            .contains("lost mapping state"));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn expired_ownership_never_sends_renew_or_delete() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let endpoints = Endpoints {
            gateway: addr(&server),
            discovery: addr(&server),
        };
        let mut mapping = Mapping::from_grant(
            local(),
            &config(),
            endpoints,
            Protocol::Pcp { nonce: [3; 12] },
            grant(external(), 50012, 120, false).unwrap(),
            Instant::now(),
        )
        .unwrap();
        mapping.expires = Instant::now();
        assert!(mapping.renew().await.is_err());
        assert!(mapping.cleanup().await.is_err());
        let mut buf = [0; 128];
        assert!(
            timeout(Duration::from_millis(50), server.recv_from(&mut buf))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn udp_wrong_tuple_and_wrong_source_are_not_grants() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let gateway = addr(&server);
        let task = tokio::spawn(async move {
            let mut buf = [0; 128];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let mut b = pcp_response(&buf[..n], 50001, 60);
            let stranger = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            stranger.send_to(&b, peer).await.unwrap();
            b[40..42].copy_from_slice(&4434u16.to_be_bytes());
            server.send_to(&b, peer).await.unwrap();
            // Keep the selected socket alive until the bounded request expires.
            tokio::time::sleep(Duration::from_millis(250)).await;
        });
        assert!(pcp_map(
            local(),
            gateway,
            [9; 12],
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 4433),
            1200,
            &config()
        )
        .await
        .is_err());
        task.await.unwrap();
    }

    #[test]
    fn grant_and_xml_boundaries_refuse_permanent_wildcard_or_cross_gateway() {
        assert!(grant(external(), 50000, 0, false).is_err());
        assert!(grant(external(), 0, 60, false).is_err());
        assert!(grant(external(), 50000, 7201, false).is_err());
        assert!(validate_local(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).is_err());
        assert!(NatConfig {
            requested_lifetime: Duration::ZERO,
            ..config()
        }
        .validate()
        .is_err());
        for url in [
            "http://evil.example/control",
            "http://127.0.0.2/control",
            "http://user@127.0.0.1/control",
            "https://127.0.0.1/control",
            "http://127.0.0.1/x#y",
        ] {
            assert!(pinned_url(url, None, Ipv4Addr::LOCALHOST).is_err());
        }
        assert!(
            xml_fields(b"<!DOCTYPE a [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><a>&x;</a>")
                .is_err()
        );
        assert!(xml_fields(b"<a><x>one</x><x>two</x></a>").is_err());
        assert!(xml_fields(b"<a><x>unfinished").is_err());
        assert_eq!(
            xml_fields(b"<a><x>A &amp; B &#49; &lt;C&gt;</x></a>").unwrap()["x"],
            "A & B 1 <C>"
        );
        assert!(xml_fields(&vec![b'x'; MAX_XML + 1]).is_err());
    }

    #[test]
    fn descriptor_service_fields_cannot_mix_and_urls_stay_on_gateway() {
        let location = Url::parse("http://127.0.0.1:1234/root.xml").unwrap();
        let xml=format!("<root><device><serviceList><service><serviceType>unrelated</serviceType><controlURL>http://evil.example/</controlURL></service><service><serviceType>{}</serviceType><controlURL>/control</controlURL></service></serviceList></device></root>",SERVICES[0]);
        let (service, url) = igd_service(xml.as_bytes(), &location, Ipv4Addr::LOCALHOST).unwrap();
        assert_eq!(service, SERVICES[0]);
        assert_eq!(url.as_str(), "http://127.0.0.1:1234/control");
        assert!(igd_service(
            xml.replace("/control", "http://127.0.0.2/control")
                .as_bytes(),
            &location,
            Ipv4Addr::LOCALHOST
        )
        .is_err());
    }

    #[test]
    fn real_platform_route_formats_select_lowest_metric() {
        let routes="Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 00000000 0101A8C0 0003 0 0 600 00000000 0 0 0\nwlan0 00000000 0100000A 0003 0 0 100 00000000 0 0 0\n";
        assert_eq!(
            parse_linux_routes(routes).unwrap(),
            Ipv4Addr::new(10, 0, 0, 1)
        );
        assert_eq!(
            parse_platform_routes("route to: default\n gateway: 192.168.1.1\n interface: en0")
                .unwrap(),
            Ipv4Addr::new(192, 168, 1, 1)
        );
        assert_eq!(parse_platform_routes("0.0.0.0 0.0.0.0 192.168.1.1 192.168.1.20 25\n0.0.0.0 0.0.0.0 10.1.0.1 10.1.0.20 50").unwrap(),Ipv4Addr::new(192,168,1,1));
    }

    #[derive(Default)]
    struct IgdState {
        description: Option<String>,
        port: u16,
        internal: u16,
        lease: u32,
        actions: Vec<String>,
        permanent: bool,
        version1: bool,
    }

    async fn igd_fixture(
        permanent: bool,
        version1: bool,
    ) -> (
        Endpoints,
        Arc<Mutex<IgdState>>,
        Vec<tokio::task::JoinHandle<()>>,
    ) {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let gateway = addr(&udp);
        let ssdp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let discovery = addr(&ssdp);
        let http = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let http_addr = http.local_addr().unwrap();
        let state = Arc::new(Mutex::new(IgdState {
            permanent,
            version1,
            ..IgdState::default()
        }));
        let shared = state.clone();
        let udp_task = tokio::spawn(async move {
            let mut buf = [0; 128];
            loop {
                let Ok((n, peer)) = udp.recv_from(&mut buf).await else {
                    break;
                };
                let mut response = if buf[0] == 2 {
                    pcp_response(&buf[..n], 0, 0)
                } else {
                    pmp_response(&buf[..n], 5, 0, 0)
                };
                response[3] = 1;
                udp.send_to(&response, peer).await.unwrap();
            }
        });
        let ssdp_task = tokio::spawn(async move {
            let mut buf = [0; 1024];
            loop {
                let Ok((n, peer)) = ssdp.recv_from(&mut buf).await else {
                    break;
                };
                assert!(std::str::from_utf8(&buf[..n])
                    .unwrap()
                    .starts_with("M-SEARCH * HTTP/1.1\r\n"));
                let response =
                    format!("HTTP/1.1 200 OK\r\nLOCATION: http://{http_addr}/root.xml\r\n\r\n");
                ssdp.send_to(response.as_bytes(), peer).await.unwrap();
            }
        });
        let http_task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = http.accept().await else {
                    break;
                };
                let mut request = Vec::new();
                let mut buf = [0; 4096];
                let body_start = loop {
                    let n = stream.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&buf[..n]);
                    if let Some(i) = request.windows(4).position(|v| v == b"\r\n\r\n") {
                        break i + 4;
                    }
                    assert!(request.len() < 8192);
                };
                let headers = String::from_utf8(request[..body_start].to_vec()).unwrap();
                let length = headers
                    .lines()
                    .filter_map(|l| l.split_once(':'))
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                    .map(|(_, v)| v.trim().parse::<usize>().unwrap())
                    .unwrap_or(0);
                while request.len() < body_start + length {
                    let n = stream.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&buf[..n]);
                }
                let (status, body) = {
                    let mut state = shared.lock().unwrap();
                    let service = if state.version1 {
                        SERVICES[1]
                    } else {
                        SERVICES[0]
                    };
                    if headers.starts_with("GET /root.xml ") {
                        (200,format!("<root><device><serviceList><service><serviceType>{service}</serviceType><controlURL>/control</controlURL></service></serviceList></device></root>"))
                    } else {
                        assert!(headers.starts_with("POST /control "));
                        let action = headers
                            .lines()
                            .filter_map(|l| l.split_once(':'))
                            .find(|(k, _)| k.eq_ignore_ascii_case("soapaction"))
                            .unwrap()
                            .1
                            .trim()
                            .trim_matches('"')
                            .split('#')
                            .next_back()
                            .unwrap()
                            .to_string();
                        state.actions.push(action.clone());
                        let fields = xml_fields(&request[body_start..body_start + length]).unwrap();
                        let mut code = None;
                        let result = match action.as_str() {
                            "GetExternalIPAddress" => format!(
                                "<NewExternalIPAddress>{}</NewExternalIPAddress>",
                                external()
                            ),
                            "GetSpecificPortMappingEntry" => {
                                assert_eq!(fields["NewProtocol"], "TCP");
                                let port = fields["NewExternalPort"].parse::<u16>().unwrap();
                                match state.description.as_ref() {
                                    Some(description) if port == state.port => format!("<NewInternalPort>{}</NewInternalPort><NewInternalClient>127.0.0.1</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>{}</NewPortMappingDescription><NewLeaseDuration>{}</NewLeaseDuration>",state.internal,description,state.lease),
                                    _ => { code = Some(714); String::new() }
                                }
                            }
                            "AddAnyPortMapping" | "AddPortMapping" => {
                                assert_eq!(fields["NewProtocol"], "TCP");
                                assert_eq!(fields["NewInternalClient"], "127.0.0.1");
                                assert_eq!(fields["NewLeaseDuration"], "1200");
                                state.internal = fields["NewInternalPort"].parse().unwrap();
                                assert_eq!(state.internal, 4433);
                                state.port = if action == "AddAnyPortMapping" {
                                    50101
                                } else {
                                    fields["NewExternalPort"].parse().unwrap()
                                };
                                state.description =
                                    Some(fields["NewPortMappingDescription"].clone());
                                state.lease = if state.permanent {
                                    0
                                } else if action == "AddPortMapping" {
                                    90
                                } else {
                                    120
                                };
                                if action == "AddAnyPortMapping" {
                                    format!("<NewReservedPort>{}</NewReservedPort>", state.port)
                                } else {
                                    String::new()
                                }
                            }
                            "DeletePortMapping" => {
                                assert_eq!(
                                    fields["NewExternalPort"].parse::<u16>().unwrap(),
                                    state.port
                                );
                                assert_eq!(fields["NewProtocol"], "TCP");
                                state.description = None;
                                String::new()
                            }
                            _ => panic!("unexpected SOAP action {action}"),
                        };
                        if let Some(code) = code {
                            (500,format!("<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><s:Fault><detail><UPnPError><errorCode>{code}</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>"))
                        } else {
                            (200,format!("<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:{action}Response xmlns:u=\"{service}\">{result}</u:{action}Response></s:Body></s:Envelope>"))
                        }
                    }
                };
                let response=format!("HTTP/1.1 {status} {}\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",if status==200{"OK"}else{"Internal Server Error"},body.len());
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        (
            Endpoints { gateway, discovery },
            state,
            vec![udp_task, ssdp_task, http_task],
        )
    }

    async fn stop_fixture(tasks: Vec<tokio::task::JoinHandle<()>>) {
        for task in tasks {
            task.abort();
            // A socket task can already have returned after a peer closes
            // (notably a delayed UDP reset on Windows). Still surface panics.
            if let Err(error) = task.await {
                assert!(error.is_cancelled(), "fixture task failed: {error}");
            }
        }
    }

    #[tokio::test]
    async fn real_ssdp_soap_fallback_grants_renews_and_only_removes_owned_mapping() {
        let (endpoints, state, tasks) = igd_fixture(false, false).await;
        let mut mapping = Mapping::create_at(local(), &config(), endpoints)
            .await
            .unwrap();
        assert!(matches!(mapping.protocol, Protocol::Igd(_)));
        assert_eq!(mapping.external_addr().port(), 50101);
        assert_eq!(mapping.lifetime(), Duration::from_secs(120));
        mapping.renew().await.unwrap();
        assert_eq!(mapping.lifetime(), Duration::from_secs(90));
        mapping.cleanup().await.unwrap();
        {
            let state = state.lock().unwrap();
            assert!(state.description.is_none());
            assert_eq!(state.actions.last().unwrap(), "DeletePortMapping");
            assert_eq!(
                state
                    .actions
                    .iter()
                    .filter(|v| *v == "AddAnyPortMapping")
                    .count(),
                1
            );
        }
        stop_fixture(tasks).await;
    }

    #[tokio::test]
    async fn igd_v1_finite_mapping_supported_and_foreign_owner_never_renewed_or_deleted() {
        let (endpoints, state, tasks) = igd_fixture(false, true).await;
        let mut mapping = Mapping::create_at(local(), &config(), endpoints)
            .await
            .unwrap();
        assert!(mapping.external_addr().port() >= 49152);
        assert_eq!(mapping.lifetime(), Duration::from_secs(90));
        state.lock().unwrap().description = Some("someone-else".into());
        assert!(mapping
            .renew()
            .await
            .unwrap_err()
            .contains("ownership changed"));
        assert!(mapping
            .cleanup()
            .await
            .unwrap_err()
            .contains("ownership changed"));
        {
            let state = state.lock().unwrap();
            assert!(!state.actions.iter().any(|v| v == "DeletePortMapping"));
            assert_eq!(
                state
                    .actions
                    .iter()
                    .filter(|v| *v == "AddPortMapping")
                    .count(),
                1
            );
        }
        stop_fixture(tasks).await;
    }

    #[tokio::test]
    async fn igd_zero_lifetime_is_not_published_or_renewed_as_permanent() {
        let (endpoints, state, tasks) = igd_fixture(true, false).await;
        let error = Mapping::create_at(local(), &config(), endpoints)
            .await
            .err()
            .unwrap();
        assert!(error.contains("permanent"));
        assert!(error.contains("cleanup confirmed"));
        assert!(state.lock().unwrap().description.is_none());
        assert_eq!(
            state.lock().unwrap().actions.last().unwrap(),
            "DeletePortMapping"
        );
        assert_eq!(
            state
                .lock()
                .unwrap()
                .actions
                .iter()
                .filter(|a| a.starts_with("Add"))
                .count(),
            1
        );
        stop_fixture(tasks).await;
    }
}
