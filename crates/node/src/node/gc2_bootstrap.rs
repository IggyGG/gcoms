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
}
