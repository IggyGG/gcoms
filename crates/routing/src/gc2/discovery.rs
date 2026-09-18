//! Authenticated GC/2 directory renewal over an explicitly supplied route.
//! This helper never chooses a direct fallback or changes entry connections.
use super::directory::{BootstrapBundle, Introduction};
use crate::{route::now_unix, Result};
use gcoms_core::{gc2::NaturalCell, CellType, TrafficClass};
use gcoms_transport::{
    gc2::{NaturalOutcome, NaturalRoute},
    Tp1Client,
};
use std::net::SocketAddr;
use zeroize::Zeroizing;

pub(crate) const REQUEST: &[u8; 4] = b"GCD2";

/// Renew even an expired introduction using its independent, stable re-entry
/// capability. The caller must validate address policy before connecting and
/// install the returned bundle through `Directory::remember`. Only background
/// startup/recovery may supply a direct client; messages must use ready routes.
pub async fn refresh(
    client: &Tp1Client,
    seed: &Introduction,
    excluded: &[(SocketAddr, [u8; 32])],
) -> Result<BootstrapBundle> {
    seed.validate()?;
    refresh_reentry(
        client,
        seed.addr,
        seed.service_id,
        seed.reentry_cap,
        excluded,
    )
    .await
}

/// Explicit migration from a retained GC/1 re-entry authority, which carries no
/// GC/2 entry or transit capability yet. The reply must still present the same
/// stable re-entry authority and a valid entry; nothing is converted implicitly
/// and a failure never falls back to GC/1.
pub async fn refresh_reentry(
    client: &Tp1Client,
    addr: SocketAddr,
    service_id: [u8; 32],
    reentry_cap: [u8; 32],
    excluded: &[(SocketAddr, [u8; 32])],
) -> Result<BootstrapBundle> {
    if service_id == [0; 32] || reentry_cap == [0; 32] {
        return Err("invalid GC/2 re-entry seed".into());
    }
    crate::wire::decode_address(&crate::wire::encode_address(addr))?;
    if excluded.len() > 64 {
        return Err("too many GC/2 discovery exclusions".into());
    }
    let token = Zeroizing::new(gcoms_transport::encode_b64url(&reentry_cap));
    let outcome = client
        .post_natural_prepared(
            NaturalRoute {
                addr,
                service_id,
                token: &token,
                excluded,
                class: TrafficClass::Interactive,
            },
            || Ok(NaturalCell::new(CellType::Pex, 0, REQUEST.to_vec())?),
        )
        .await?;
    let NaturalOutcome::Accepted(Some(cell)) = outcome else {
        return Err("GC/2 private discovery refused".into());
    };
    if cell.kind() != CellType::Pex || cell.flags() != 0 {
        return Err("invalid GC/2 private discovery response".into());
    }
    let bundle = BootstrapBundle::decode(cell.payload())?;
    let own = bundle
        .relays
        .iter()
        .find(|relay| relay.service_id == service_id)
        .ok_or("GC/2 discovery omitted its authenticated service")?;
    // Pin authentication does not authorize an implicit capability migration.
    // A stable re-entry authority is retained only across explicit v2 renewal.
    if own.reentry_cap != reentry_cap {
        return Err("GC/2 discovery changed its stable re-entry authority".into());
    }
    own.entry(now_unix())?;
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reentry_seed_requires_nonzero_authorities() {
        let client = Tp1Client::new().unwrap();
        let addr = "127.0.0.1:1".parse().unwrap();
        assert!(refresh_reentry(&client, addr, [0; 32], [1; 32], &[])
            .await
            .is_err());
        assert!(refresh_reentry(&client, addr, [1; 32], [0; 32], &[])
            .await
            .is_err());
    }
}
