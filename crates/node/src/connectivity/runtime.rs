use super::{nat, ConnectivityConfig};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::watch;

type CandidateUpdate = Arc<dyn Fn(SocketAddr) -> Result<(), String> + Send + Sync>;

pub(crate) struct RuntimeTask {
    stop: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for RuntimeTask {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}

impl RuntimeTask {
    pub(crate) async fn shutdown(mut self) {
        self.stop.send_replace(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

pub(crate) fn spawn(
    config: ConnectivityConfig,
    bound: SocketAddr,
    advertised: Option<SocketAddr>,
    update: CandidateUpdate,
    published: Arc<AtomicBool>,
) -> RuntimeTask {
    let (stop, mut stopped) = watch::channel(false);
    let task = tokio::spawn(async move {
        let mut mapping: Option<nat::Mapping> = None;
        let mut failures = 0u32;
        let mut next_attempt = Instant::now();
        let mut next_renewal = Instant::now();
        let mut expires = Instant::now();
        loop {
            if *stopped.borrow() {
                break;
            }
            let local = local_address(bound).await;
            if let Some(ref mut grant) = mapping {
                // A changed interface/source route invalidates only reachability;
                // the listener, TLS principal and encrypted node archives survive.
                if local.as_ref().ok().copied() != Some(SocketAddr::V4(grant.local_addr())) {
                    published.store(false, Ordering::Release);
                    let _ = update(local.unwrap_or(bound));
                    let _ = grant.cleanup().await;
                    mapping = None;
                    next_attempt = Instant::now();
                } else if Instant::now() >= next_renewal {
                    let remaining = expires.saturating_duration_since(Instant::now());
                    let renewed = tokio::time::timeout(remaining, grant.renew()).await;
                    if renewed.is_ok_and(|r| r.is_ok()) {
                        if update(SocketAddr::V4(grant.external_addr())).is_err() {
                            break;
                        }
                        expires = Instant::now() + grant.remaining_lifetime();
                        next_renewal = renewal_deadline(grant.remaining_lifetime());
                    } else {
                        published.store(false, Ordering::Release);
                        let _ = update(local.unwrap_or(bound));
                        let _ = grant.cleanup().await;
                        mapping = None;
                        failures = failures.saturating_add(1);
                        next_attempt = Instant::now() + retry_delay(failures);
                    }
                }
            } else if Instant::now() >= next_attempt {
                let candidate = advertised.or(local.ok()).unwrap_or(bound);
                if update(candidate).is_err() {
                    break;
                }
                let directly_public = gcoms_routing::service::public_ip(candidate.ip());
                if config.mapping && advertised.is_none() && !directly_public {
                    if let SocketAddr::V4(local) = candidate {
                        if !local.ip().is_loopback() && !local.ip().is_unspecified() {
                            match nat::Mapping::create(local, &config.nat).await {
                                Ok(grant) => {
                                    if update(SocketAddr::V4(grant.external_addr())).is_err() {
                                        let mut grant = grant;
                                        let _ = grant.cleanup().await;
                                        break;
                                    }
                                    expires = Instant::now() + grant.remaining_lifetime();
                                    next_renewal = renewal_deadline(grant.remaining_lifetime());
                                    mapping = Some(grant);
                                    failures = 0;
                                }
                                Err(_) => {
                                    published.store(false, Ordering::Release);
                                    failures = failures.saturating_add(1);
                                }
                            }
                        }
                    }
                }
                next_attempt = Instant::now() + retry_delay(failures);
            }
            let delay = if mapping.is_some() {
                next_renewal
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_secs(30))
            } else {
                next_attempt
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_secs(30))
            }
            .max(Duration::from_millis(50));
            tokio::select! {
                _ = tokio::time::sleep(delay) => {},
                _ = stopped.changed() => break,
            }
        }
        published.store(false, Ordering::Release);
        if let Some(mut grant) = mapping {
            let _ = grant.cleanup().await;
        }
    });
    RuntimeTask {
        stop,
        task: Some(task),
    }
}

fn renewal_deadline(lifetime: Duration) -> Instant {
    // Renew before half-life, with jitter to avoid synchronized gateway bursts.
    let fraction = 40 + rand::random::<u32>() % 11;
    Instant::now() + lifetime.mul_f64(fraction as f64 / 100.0)
}

fn retry_delay(failures: u32) -> Duration {
    let base = 5u64.saturating_mul(1 << failures.min(6)).min(300);
    Duration::from_secs(base + rand::random::<u64>() % (base / 4 + 1))
}

async fn local_address(bound: SocketAddr) -> Result<SocketAddr, String> {
    if !bound.ip().is_unspecified() {
        return Ok(bound);
    }
    if bound.is_ipv4() {
        return nat::resolve_local(bound).await.map(SocketAddr::V4);
    }
    let socket = tokio::net::UdpSocket::bind("[::]:0")
        .await
        .map_err(|e| e.to_string())?;
    // UDP connect selects the OS source route; it sends no packet.
    socket
        .connect("[2606:4700:4700::1111]:9")
        .await
        .map_err(|e| e.to_string())?;
    Ok(SocketAddr::new(
        socket.local_addr().map_err(|e| e.to_string())?.ip(),
        bound.port(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn renewal_and_failure_backoff_are_bounded_and_jittered() {
        for failures in 0..100 {
            let retry = retry_delay(failures);
            assert!(retry >= Duration::from_secs(5));
            assert!(retry <= Duration::from_secs(375));
        }
        for seconds in [1, 20, 1200, 7200] {
            let started = Instant::now();
            let deadline = renewal_deadline(Duration::from_secs(seconds));
            assert!(deadline > started);
            assert!(deadline < started + Duration::from_secs(seconds));
        }
    }
}
