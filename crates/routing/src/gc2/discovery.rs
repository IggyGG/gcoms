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
    if excluded.len() > 64 {
        return Err("too many GC/2 discovery exclusions".into());
    }
    let token = Zeroizing::new(gcoms_transport::encode_b64url(&seed.reentry_cap));
    let outcome = client
        .post_natural_prepared(
            NaturalRoute {
                addr: seed.addr,
                service_id: seed.service_id,
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
        .find(|relay| relay.service_id == seed.service_id)
        .ok_or("GC/2 discovery omitted its authenticated service")?;
    // Pin authentication does not authorize an implicit capability migration.
    // A stable re-entry authority is retained only across explicit v2 renewal.
    if own.reentry_cap != seed.reentry_cap {
        return Err("GC/2 discovery changed its stable re-entry authority".into());
    }
    own.entry(now_unix())?;
    Ok(bundle)
}
