//! Explicit GC/2 bootstrap from an authenticated provisioning advertisement.
//!
//! A GC/1 re-entry capability cannot authenticate the GC/2 control role; the
//! relay advertises its GC/2 introduction in response to an opted-in private
//! provisioning request. The client installs that introduction as a directory
//! seed and the background owner renews it. Nothing is converted implicitly
//! and a failure never falls back to GC/1.
#![cfg(feature = "experimental-gc2")]

use super::now_unix;
use gcoms_routing::gc2::directory::{BootstrapBundle, Directory, Introduction};
use std::sync::Arc;

pub(crate) struct Prepared {
    pub directory: Arc<Directory>,
    pub owner: gcoms_routing::gc2::owner::EntryOwner,
    pub ready: Arc<gcoms_routing::gc2::owner::ReadyConnector>,
}

pub(crate) fn prepare(
    cfg: &super::NodeConfig,
    runtime: Option<&Arc<super::routing::RoutingRuntime>>,
) -> Result<Option<Prepared>, String> {
    let Some((path, entries, _, _, _)) = cfg.profile.gc2_carrier() else {
        if runtime.is_some_and(|r| r.gc2_bootstrap.is_some()) {
            return Err("GCRB2 bootstrap requires the GChat carrier profile".into());
        }
        return Ok(None);
    };
    let profile = cfg.profile.gc2_wire_profile()?;
    let directory = Arc::new(match path {
        Some(path) => crate::routing_cache::Cache::open_gc2(path, &cfg.seed)
            .and_then(|cache| {
                cache.select_gc2_profile(profile)?;
                cache.gc2_directory(super::now_unix())
            })
            .map_err(|e| e.to_string())?,
        None if cfg.profile.gc2_loopback_fixture() => Directory::for_loopback_fixture(),
        None => Directory::new(),
    });
    if let Some(bundle) = runtime.and_then(|r| r.gc2_bootstrap.as_ref()) {
        directory
            .remember(bundle, super::now_unix())
            .map_err(|e| e.to_string())?;
    }
    for introduction in cfg.profile.gc2_introductions() {
        install_advertised(&directory, introduction)?;
    }
    let (owner, ready) =
        gcoms_routing::gc2::owner::EntryOwner::new(directory.clone(), profile, entries)
            .map_err(|e| e.to_string())?;
    if let Some(runtime) = runtime {
        let control = Arc::new(
            gcoms_transport::Tp1Client::with_connector(ready.clone()).map_err(|e| e.to_string())?,
        );
        runtime
            .gc2
            .set(super::routing::Gc2Routing {
                profile_id: profile.id(),
                directory: directory.clone(),
                ready: ready.clone(),
                control,
            })
            .map_err(|_| "GChat routing already initialized")?;
    }
    Ok(Some(Prepared {
        directory,
        owner,
        ready,
    }))
}

/// Install one advertised introduction as a canonical directory seed. The
/// directory's own address policy, expiry and capability validation apply;
/// a malformed or expired advertisement fails closed.
pub(crate) fn install_advertised(directory: &Directory, bytes: &[u8]) -> Result<usize, String> {
    let introduction = Introduction::decode(bytes).map_err(|error| error.to_string())?;
    // An advertisement must be fresh; an expired seed is never installed as a
    // new introduction.
    if introduction.expires_at <= now_unix() {
        return Err("expired GC/2 advertisement".into());
    }
    introduction
        .entry(now_unix())
        .map_err(|error| error.to_string())?;
    let bundle = BootstrapBundle {
        relays: vec![introduction],
    };
    directory
        .remember(&bundle, now_unix())
        .map_err(|error| error.to_string())
}

/// Install a full GC/2 bootstrap bundle fetched over an authenticated HTTPS
/// channel as directory seeds for the carrier profile. Every introduction is
/// validated against expiry before any is remembered.
pub(crate) fn install_bundle(directory: &Directory, bytes: &[u8]) -> Result<usize, String> {
    let bundle = BootstrapBundle::decode(bytes).map_err(|error| error.to_string())?;
    for introduction in &bundle.relays {
        if introduction.expires_at <= now_unix() {
            return Err("expired GC/2 bootstrap bundle".into());
        }
    }
    directory
        .remember(&bundle, now_unix())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gcoms_routing::service::gc2_introduction_from;

    const RELAY: &str = "93.184.216.34:443";

    #[test]
    fn advertised_introduction_installs_and_expired_or_tampered_fails_closed() {
        let directory = Directory::new();
        let introduction =
            gc2_introduction_from(RELAY.parse().unwrap(), [0x31; 32], &[0x32; 32], now_unix());
        let bytes = introduction.encode().unwrap();
        assert_eq!(install_advertised(&directory, &bytes[..]).unwrap(), 1);
        assert_eq!(directory.reentry_candidates().len(), 1);

        let expired = gc2_introduction_from(
            RELAY.parse().unwrap(),
            [0x33; 32],
            &[0x34; 32],
            now_unix().saturating_sub(4 * 3600),
        );
        assert!(install_advertised(&directory, &expired.encode().unwrap()[..]).is_err());
        assert!(install_advertised(&directory, &[0xA5; 155]).is_err());
        assert!(install_advertised(&directory, &[]).is_err());
        assert!(install_advertised(&directory, &bytes[..154]).is_err());
    }

    #[test]
    fn bootstrap_bundle_installs_fresh_introductions_and_rejects_expired() {
        let directory = Directory::new();
        let fresh = gc2_introduction_from(
            RELAY.parse().unwrap(),
            [0x41; 32],
            &[0x42; 32],
            now_unix(),
        );
        let stale = gc2_introduction_from(
            "93.184.216.35:443".parse().unwrap(),
            [0x43; 32],
            &[0x44; 32],
            now_unix().saturating_sub(4 * 3600),
        );
        let bundle = BootstrapBundle {
            relays: vec![fresh.clone()],
        };
        assert_eq!(
            install_bundle(&directory, &bundle.encode().unwrap()[..]).unwrap(),
            1
        );
        assert_eq!(directory.reentry_candidates().len(), 1);
        // A bundle with any expired introduction fails closed, installing none.
        let mixed = BootstrapBundle {
            relays: vec![
                gc2_introduction_from(
                    "93.184.216.36:443".parse().unwrap(),
                    [0x45; 32],
                    &[0x46; 32],
                    now_unix(),
                ),
                stale,
            ],
        };
        assert!(install_bundle(&directory, &mixed.encode().unwrap()[..]).is_err());
        assert!(install_bundle(&directory, &[0xA5; 32]).is_err());
    }
}
