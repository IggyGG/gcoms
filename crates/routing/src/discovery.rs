//! Re-entry and referral recovery, independent of application/queue lifetimes.
use crate::{
    carrier, route::now_unix, service::public_ip, Directory, OnionConnector, Relay, Result,
};
use gcoms_transport::connector::{Connector, DirectConnector};
use rand::seq::SliceRandom;
use std::{net::SocketAddr, sync::Arc, time::Duration};

pub struct Discovery {
    pub directory: Arc<Directory>,
    pub connector: Arc<OnionConnector>,
    allow_local_fixture: bool,
}

impl Discovery {
    pub fn new(directory: Arc<Directory>, connector: Arc<OnionConnector>) -> Self {
        Self {
            directory,
            connector,
            allow_local_fixture: false,
        }
    }

    /// Only an explicit disposable fixture may admit private relay addresses.
    pub fn with_local_fixture(mut self) -> Self {
        self.allow_local_fixture = true;
        self
    }

    pub fn install(&self, bundle: &crate::bootstrap::BootstrapBundle) -> Result<usize> {
        bundle.validate()?;
        if !self.allow_local_fixture && bundle.relays.iter().any(|r| !public_ip(r.addr.ip())) {
            return Err("bootstrap contains a nonpublic relay".into());
        }
        bundle.install_fresh(&self.directory, now_unix())
    }

    /// Direct contact is confined to private re-entry when no complete path
    /// exists. Once a path exists, refreshes go through it. An application or
    /// provisioning error can never enter this narrow bootstrap operation.
    pub async fn refresh(&self) -> Result<usize> {
        let mut installed = 0;
        for seed in self.directory.reentry_candidates() {
            if !self.allow_local_fixture && !public_ip(seed.addr.ip()) {
                continue;
            }
            let result = tokio::time::timeout(Duration::from_secs(45), async {
                let stream = if self
                    .directory
                    .path(&[(seed.addr, seed.service_id)], now_unix())
                    .is_ok()
                {
                    self.connector.connect(seed.addr, seed.service_id).await?
                } else {
                    DirectConnector.connect(seed.addr, seed.service_id).await?
                };
                carrier::refresh(stream, &seed).await
            })
            .await;
            match result {
                Ok(Ok(relays)) => {
                    for relay in relays {
                        if (self.allow_local_fixture || public_ip(relay.addr.ip()))
                            && self.directory.install(relay, now_unix()).is_ok()
                        {
                            installed += 1;
                        }
                    }
                    self.directory.healthy(seed.service_id);
                    // One authenticated response per round suffices; another
                    // retained guard is tried only on failure, limiting exposure.
                    return Ok(installed);
                }
                _ => self.directory.failed(seed.service_id),
            }
        }
        Err("no retained relay answered private re-entry".into())
    }

    /// Pick an inbox independently of the two intermediate hops. No identity or
    /// queue capability is sent until the complete pinned circuit exists.
    pub async fn provision(
        &self,
        request_id: [u8; 32],
        excluded: &[(SocketAddr, [u8; 32])],
    ) -> Result<(Relay, zeroize::Zeroizing<Vec<u8>>)> {
        let mut candidates = self.directory.introductions();
        candidates.shuffle(&mut rand::thread_rng());
        candidates.retain(|r| {
            r.expires_at > now_unix()
                && !self.directory.is_own(r.addr, r.service_id)
                && (self.allow_local_fixture || public_ip(r.addr.ip()))
                && !excluded.iter().any(|(addr, pin)| r.conflicts(*addr, *pin))
        });
        for relay in candidates.into_iter().take(4) {
            let Ok(stream) = self
                .connector
                .connect_excluding(relay.addr, relay.service_id, excluded)
                .await
            else {
                continue;
            };
            if let Ok(reply) = carrier::provision(stream, &relay, request_id).await {
                return Ok((relay, reply));
            }
        }
        Err("no complete circuit to an available inbox service".into())
    }

    pub async fn publish(&self, own: &Relay) -> Result<()> {
        if !self.allow_local_fixture && !public_ip(own.addr.ip()) {
            return Err("outbound-only client has no public relay listener".into());
        }
        let mut candidates = self.directory.introductions();
        candidates.shuffle(&mut rand::thread_rng());
        for relay in candidates
            .into_iter()
            .filter(|r| !r.conflicts(own.addr, own.service_id))
            .take(4)
        {
            let Ok(stream) = self
                .connector
                .connect_excluding(relay.addr, relay.service_id, &[(own.addr, own.service_id)])
                .await
            else {
                continue;
            };
            if carrier::advertise(stream, &relay, own).await.is_ok() {
                return Ok(());
            }
        }
        Err("no independent relay verified public reachability".into())
    }
}
