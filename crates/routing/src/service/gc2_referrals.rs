//! Relay-owned renewal of already authorized public referrals. This directory
//! is deliberately separate from the client's private guards and discoveries.
use super::*;
use crate::gc2::{directory::BootstrapBundle, discovery};
use futures_util::{stream, StreamExt};
use tokio::time::{sleep, timeout, Instant as TokioInstant};

impl RelayService {
    /// Run as a host-owned background task and cancel it with the host. Requests
    /// cannot trigger renewal. Only the authenticated peer's own introduction is
    /// retained: its referrals cannot expand this relay's disclosure boundary.
    pub async fn run_gc2_referral_refresh(&self) -> Result<()> {
        let client = gcoms_transport::Tp1Client::new()?;
        let mut schedule = HashMap::<[u8; 32], (TokioInstant, u32)>::new();
        loop {
            // A compiled listener is not permission to act as a public relay.
            // Desktop loopback services must keep their retained-guard boundary.
            if !self.gc2_referral_publication_allowed() {
                sleep(Duration::from_secs(1)).await;
                continue;
            }
            // Directory enforces address policy and bounds this list to eight.
            let candidates: Vec<_> = self
                .gc2_directory
                .reentry_candidates()
                .into_iter()
                .filter(|seed| !seed.conflicts(self.address(), self.service_id))
                .collect();
            schedule.retain(|pin, _| candidates.iter().any(|seed| &seed.service_id == pin));
            let due: Vec<_> = candidates
                .into_iter()
                .filter(|seed| {
                    schedule
                        .get(&seed.service_id)
                        .is_none_or(|(next, _)| *next <= TokioInstant::now())
                })
                .collect();
            let mut pending = stream::iter(due.into_iter().map(|seed| {
                let client = &client;
                async move {
                    let current = || {
                        self.gc2_referral_publication_allowed()
                            && self.gc2_directory.reentry_candidates().iter().any(|old| {
                                old.service_id == seed.service_id
                                    && old.addr == seed.addr
                                    && old.reentry_cap == seed.reentry_cap
                                    && !old.conflicts(self.address(), self.service_id)
                            })
                    };
                    let mut renewed = None;
                    if current() {
                        if let Ok(Ok(bundle)) = timeout(
                            Duration::from_secs(20),
                            discovery::refresh(client, &seed, &[]),
                        )
                        .await
                        {
                            if let Some(own) = bundle
                                .relays
                                .iter()
                                .find(|r| r.service_id == seed.service_id && r.addr == seed.addr)
                                .filter(|_| current())
                                .cloned()
                            {
                                let expiry = own.expires_at;
                                if self
                                    .gc2_directory
                                    .remember(&BootstrapBundle { relays: vec![own] }, now_unix())
                                    .is_ok()
                                {
                                    renewed = Some(expiry);
                                }
                            }
                        }
                    }
                    (seed.service_id, renewed)
                }
            }))
            .buffer_unordered(4);
            while let Some((pin, expiry)) = pending.next().await {
                let failures = if expiry.is_some() {
                    0
                } else {
                    schedule
                        .get(&pin)
                        .map_or(1, |(_, n)| n.saturating_add(1).min(6))
                };
                let seconds = match expiry {
                    // The old credential is never extended. Fetch the next
                    // epoch just after it becomes available, or at five minutes.
                    Some(expiry) => expiry.saturating_sub(now_unix()).saturating_add(1).min(300),
                    None => (5 * (1u64 << failures.saturating_sub(1))).min(300),
                };
                let jitter = Duration::from_millis(rand::random::<u64>() % 1001);
                schedule.insert(
                    pin,
                    (
                        TokioInstant::now() + Duration::from_secs(seconds) + jitter,
                        failures,
                    ),
                );
            }
            sleep(Duration::from_secs(1)).await;
        }
    }

    fn gc2_referral_publication_allowed(&self) -> bool {
        (self.policy.target_allowed)(self.address())
            && self
                .policy
                .transit_ready
                .as_ref()
                .is_none_or(|ready| ready.load(std::sync::atomic::Ordering::Acquire))
    }
}
