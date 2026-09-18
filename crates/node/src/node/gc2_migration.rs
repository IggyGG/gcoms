//! Explicit GC/2 bootstrap migration from retained GC/1 introductions.
//!
//! A GC/1 re-entry authority is a stable capability shared with the GC/2
//! introduction for the same service. Migration offers that authority through
//! the authenticated private PEX exchange; the reply must present the same
//! stable authority and a valid GC/2 entry before anything is installed.
//! Nothing is converted implicitly and a failure never falls back to GC/1.
#![cfg(feature = "experimental-gc2")]

use super::routing::RoutingRuntime;
use super::{metrics, now_unix};
use gcoms_routing::gc2::directory::Directory;
use gcoms_routing::gc2::discovery;
use gcoms_transport::Tp1Client;
use std::sync::Arc;

/// At most this many retained introductions are offered per round. Background
/// retry pacing is owned by the caller; no application event changes it.
pub(crate) const MAX_SEEDS_PER_ROUND: usize = 8;

/// One bounded migration round. Returns the number of installed introductions.
pub(crate) async fn migrate_once(
    directory: &Arc<Directory>,
    runtime: &RoutingRuntime,
    client: &Tp1Client,
) -> usize {
    let seeds = runtime.discovery.directory.reentry_candidates();
    let mut installed = 0;
    for seed in seeds.into_iter().take(MAX_SEEDS_PER_ROUND) {
        match discovery::refresh_reentry(client, seed.addr, seed.service_id, seed.reentry_cap, &[])
            .await
        {
            Ok(bundle) => match directory.remember(&bundle, now_unix()) {
                Ok(count) => {
                    installed += count;
                    metrics::log_event("gc2_migration_installed", &[("n", count.to_string())]);
                }
                Err(error) => {
                    metrics::log_event("gc2_migration_rejected", &[("e", error.to_string())])
                }
            },
            Err(error) => metrics::log_event("gc2_migration_deferred", &[("e", error.to_string())]),
        }
    }
    installed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::RoutingConfig;

    #[tokio::test]
    async fn migration_without_retained_seeds_is_a_no_op() {
        let runtime = RoutingRuntime::new(
            RoutingConfig::default(),
            gcoms_routing::Directory::new(),
            true,
        )
        .unwrap();
        let directory = Arc::new(Directory::new());
        let client = Tp1Client::new().unwrap();
        assert_eq!(migrate_once(&directory, &runtime, &client).await, 0);
    }
}
