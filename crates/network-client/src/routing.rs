//! Strict HTTPS provisioning envelopes. These decoders validate introductions;
//! callers must authenticate the HTTPS provider before passing a response here.
//! Envelope versions and routing-bundle versions are separate namespaces.
use super::{canonical_b64, now_unix, Result};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyReply {
    version: u8,
    routing_bundle_b64: String,
}

pub(crate) fn decode_legacy_response(
    bytes: &[u8],
) -> Result<gcoms_routing::bootstrap::BootstrapBundle> {
    if bytes.len() > gcoms_network::MAX_DOCUMENT_BYTES {
        return Err("network response exceeds bound".into());
    }
    let reply: LegacyReply =
        serde_json::from_slice(bytes).map_err(|_| "invalid network bootstrap response")?;
    if reply.version != 2 {
        return Err("network bootstrap version mismatch".into());
    }
    let bundle = gcoms_routing::bootstrap::BootstrapBundle::decode(&canonical_b64(
        &reply.routing_bundle_b64,
    )?)
    .map_err(|_| "invalid network relay bundle")?;
    if bundle
        .relays
        .iter()
        .any(|r| !gcoms_routing::service::public_ip(r.addr.ip()) || r.expires_at <= now_unix())
    {
        return Err("network relay must be public".into());
    }
    Ok(bundle)
}

/// Decode only envelope v3, explicitly marked GC/2, containing fresh public
/// GCRB2 introductions. There is no conversion from earlier authorities.
#[cfg(feature = "experimental-gc2")]
pub fn decode_gc2_response(bytes: &[u8]) -> Result<gcoms_routing::gc2::directory::BootstrapBundle> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reply {
        version: u8,
        routing_protocol: String,
        routing_bundle_b64: String,
    }
    if bytes.len() > gcoms_network::MAX_DOCUMENT_BYTES {
        return Err("network response exceeds bound".into());
    }
    let reply: Reply =
        serde_json::from_slice(bytes).map_err(|_| "invalid GC/2 network bootstrap response")?;
    if reply.version != 3 || reply.routing_protocol != "gc2" {
        return Err("GC/2 network bootstrap version mismatch".into());
    }
    let bundle = gcoms_routing::gc2::directory::BootstrapBundle::decode(&canonical_b64(
        &reply.routing_bundle_b64,
    )?)
    .map_err(|_| "invalid GC/2 network relay bundle")?;
    let now = now_unix();
    if bundle
        .relays
        .iter()
        .any(|r| !gcoms_routing::service::public_ip(r.addr.ip()) || r.entry(now).is_err())
    {
        return Err("GC/2 network relays must be fresh and public".into());
    }
    Ok(bundle)
}

#[cfg(all(test, feature = "experimental-gc2"))]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use gcoms_routing::gc2::directory::BootstrapBundle;
    use serde_json::json;

    fn introduction() -> gcoms_routing::gc2::directory::Introduction {
        gcoms_routing::service::gc2_introduction_from(
            "8.8.8.8:4433".parse().unwrap(),
            [3; 32],
            &[4; 32],
            now_unix(),
        )
    }

    fn response(bundle: &BootstrapBundle) -> serde_json::Value {
        json!({"version":3,"routing_protocol":"gc2",
            "routing_bundle_b64":URL_SAFE_NO_PAD.encode(bundle.encode().unwrap())})
    }

    #[test]
    fn current_response_is_typed_and_rejects_downgrade_or_ambiguous_envelopes() {
        let bundle = BootstrapBundle {
            relays: vec![introduction()],
        };
        let good = response(&bundle);
        assert_eq!(
            decode_gc2_response(&serde_json::to_vec(&good).unwrap())
                .unwrap()
                .encode()
                .unwrap(),
            bundle.encode().unwrap()
        );
        for change in [
            json!({"version":2}),
            json!({"routing_protocol":"gc1"}),
            json!({"private_card_b64":"AA"}),
            json!({"routing_bundle_b64":"Zg=="}),
        ] {
            let mut bad = good.clone();
            for (key, value) in change.as_object().unwrap() {
                bad[key] = value.clone();
            }
            assert!(decode_gc2_response(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        let legacy = gcoms_routing::bootstrap::BootstrapBundle {
            relays: vec![gcoms_routing::Relay {
                addr: "8.8.8.8:4433".parse().unwrap(),
                service_id: [3; 32],
                reentry_cap: [4; 32],
                circuit_cap: [5; 32],
                expires_at: now_unix() + 60,
            }],
        };
        let mut wrong_wire = good;
        wrong_wire["routing_bundle_b64"] = json!(URL_SAFE_NO_PAD.encode(legacy.encode().unwrap()));
        assert!(decode_gc2_response(&serde_json::to_vec(&wrong_wire).unwrap()).is_err());
        assert!(decode_legacy_response(&serde_json::to_vec(&response(&bundle)).unwrap()).is_err());
    }

    #[test]
    fn current_response_rejects_stale_private_overlong_and_overlapping_authorities() {
        for case in 0..5 {
            let mut intro = introduction();
            match case {
                0 => intro.expires_at = now_unix(),
                1 => intro.expires_at = now_unix() + 25 * 3600,
                2 => intro.addr = "127.0.0.1:4433".parse().unwrap(),
                3 => intro.addr = "192.168.1.1:4433".parse().unwrap(),
                _ => intro.addr = "[::1]:4433".parse().unwrap(),
            }
            let bad = response(&BootstrapBundle {
                relays: vec![intro],
            });
            assert!(decode_gc2_response(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        let mut intro = introduction();
        intro.entry_cap = intro.transit_cap;
        assert!(BootstrapBundle {
            relays: vec![intro]
        }
        .encode()
        .is_err());
        assert!(decode_gc2_response(&vec![b' '; gcoms_network::MAX_DOCUMENT_BYTES + 1]).is_err());
    }
}
