use crate::{
    carrier::{self, CarrierConfig},
    wire::Target,
    Directory, Result,
};
use gcoms_transport::connector::{BoxStream, ConnectFuture, Connector, DirectConnector};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

pub struct OnionConnector {
    directory: Arc<Directory>,
    config: CarrierConfig,
    first_hop: Arc<dyn Connector>,
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl OnionConnector {
    pub fn new(directory: Arc<Directory>) -> Self {
        Self {
            directory,
            config: CarrierConfig::default(),
            first_hop: Arc::new(DirectConnector),
        }
    }

    pub fn with_carrier_config(mut self, config: CarrierConfig) -> Result<Self> {
        self.config = config.validate()?;
        Ok(self)
    }

    /// The connector here is used only to dial the entry; tests can observe
    /// actual destinations without changing circuit construction or TLS.
    pub fn with_entry_connector(mut self, connector: Arc<dyn Connector>) -> Self {
        self.first_hop = connector;
        self
    }

    pub async fn connect_excluding(
        &self,
        addr: SocketAddr,
        pin: [u8; 32],
        excluded: &[(SocketAddr, [u8; 32])],
    ) -> Result<BoxStream> {
        let mut excluded = excluded.to_vec();
        excluded.push((addr, pin));
        tokio::time::timeout(
            std::time::Duration::from_secs(45),
            self.construct(
                Target::Relay {
                    addr,
                    service_id: pin,
                },
                &excluded,
            ),
        )
        .await
        .map_err(|_| "onion construction deadline exceeded")?
    }

    /// Returns a byte stream to a configured HTTPS origin. DNS is performed by
    /// the last relay; the caller must authenticate HTTPS with the origin's
    /// ordinary WebPKI trust after this independently pinned circuit completes.
    pub async fn connect_https(&self, host: &str, allowed_origins: &[String]) -> Result<BoxStream> {
        if !crate::wire::valid_host(host) || !allowed_origins.iter().any(|origin| origin == host) {
            return Err("catalog origin is not configured".into());
        }
        tokio::time::timeout(
            std::time::Duration::from_secs(45),
            self.construct(
                Target::Https {
                    host: host.into(),
                    port: 443,
                },
                &[],
            ),
        )
        .await
        .map_err(|_| "catalog circuit construction deadline exceeded")?
    }

    async fn construct(
        &self,
        target: Target,
        excluded: &[(SocketAddr, [u8; 32])],
    ) -> Result<BoxStream> {
        // Bounded reconstruction only. A terminal stream is never returned until
        // both intermediaries have independently authenticated and extended.
        // Keep this round's failures excluded even when slow OS connection
        // attempts outlive the directory's cooldown. Otherwise a dead preferred
        // entry can consume the bounded retries before volunteers are tried.
        let mut unavailable = excluded.to_vec();
        for _ in 0..4 {
            let [entry, middle] = self.directory.path(&unavailable, now_unix())?;
            let raw = match self.first_hop.connect(entry.addr, entry.service_id).await {
                Ok(raw) => raw,
                Err(_) => {
                    self.directory.failed(entry.service_id);
                    unavailable.push((entry.addr, entry.service_id));
                    continue;
                }
            };
            let middle_target = Target::Relay {
                addr: middle.addr,
                service_id: middle.service_id,
            };
            let to_middle = match carrier::open(raw, &entry, &middle_target, self.config).await {
                Ok(stream) => stream,
                // An entry can fail to reach a middle. Do not convert an
                // ambiguous extension failure into permanent middle eviction.
                Err(_) => {
                    self.directory.failed(entry.service_id);
                    unavailable.push((entry.addr, entry.service_id));
                    continue;
                }
            };
            let to_target = match carrier::open(to_middle, &middle, &target, self.config).await {
                Ok(stream) => stream,
                Err(_) => {
                    self.directory.failed(middle.service_id);
                    unavailable.push((middle.addr, middle.service_id));
                    continue;
                }
            };
            self.directory.healthy(entry.service_id);
            self.directory.healthy(middle.service_id);
            return Ok(to_target);
        }
        Err("complete onion circuit could not be established".into())
    }
}

impl Connector for OnionConnector {
    fn connect(&self, addr: SocketAddr, service_id: [u8; 32]) -> ConnectFuture<'_> {
        Box::pin(self.connect_excluding(addr, service_id, &[]))
    }

    fn connect_excluding<'a>(
        &'a self,
        addr: SocketAddr,
        service_id: [u8; 32],
        excluded: &'a [(SocketAddr, [u8; 32])],
    ) -> ConnectFuture<'a> {
        Box::pin(OnionConnector::connect_excluding(
            self, addr, service_id, excluded,
        ))
    }
}
