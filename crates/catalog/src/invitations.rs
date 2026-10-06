//! Bounded ciphertext rendezvous. Publication requires a current scoped network
//! grant and the pinned issuer signature. This service has no membership secret.
use super::*;
use gcoms_network::channel_invitation::{Descriptor, MAX_DESCRIPTOR_BYTES};
use std::io::Read;
const MAX_RECORDS: usize = 10_000;
// One scoped publisher can own several channels, each with its own invitation
// ledger. Bound the aggregate separately from the per-channel admission limit.
const MAX_RECORDS_PER_GRANT: usize = 1024;
const MAX_ACTIVE_BYTES: usize = 128 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    issuer: String,
    grant: String,
    sequence: u64,
    retain_until: u64,
    digest: [u8; 32],
    descriptor: Option<Descriptor>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Store {
    entries: BTreeMap<String, Entry>,
}
impl Store {
    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default())
            }
            Err(_) => return Err("cannot read invitation directory".into()),
        };
        let mut bytes = Vec::new();
        file.take((MAX_ACTIVE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read invitation directory")?;
        if bytes.len() > MAX_ACTIVE_BYTES {
            return Err("invitation directory exceeds bound".into());
        }
        let store: Self =
            serde_json::from_slice(&bytes).map_err(|_| "invalid invitation directory")?;
        if store.entries.len() > MAX_RECORDS {
            return Err("invitation directory exceeds record limit".into());
        }
        for (id, entry) in &store.entries {
            if URL_SAFE_NO_PAD.decode(id).is_err() || entry.sequence == 0 {
                return Err("invalid invitation tombstone".into());
            }
            if let Some(d) = &entry.descriptor {
                d.verify(d.body.issued_at)?;
                if &d.body.id != id
                    || d.body.sequence != entry.sequence
                    || d.body.issuer_key != entry.issuer
                    || digest(d)? != entry.digest
                {
                    return Err("invalid retained invitation descriptor".into());
                }
            }
        }
        Ok(store)
    }
    fn stage(&mut self, d: Descriptor, grant: String, now: u64) -> Result<bool, ApiError> {
        d.verify(now)
            .map_err(|_| ApiError::bad("invalid invitation descriptor"))?;
        let hash = digest(&d).map_err(internal_error)?;
        // Every previously accepted signature is expired after this horizon.
        // Clients independently retain sequence floors. Avoid a permanent
        // quota leak from revoked/rotated invitations without allowing a live
        // old descriptor to be replayed into a recycled slot.
        self.entries.retain(|_, entry| entry.retain_until > now);
        if let Some(old) = self.entries.get(&d.body.id) {
            if old.issuer != d.body.issuer_key
                || d.body.sequence < old.sequence
                || (d.body.sequence == old.sequence && hash != old.digest)
            {
                return Err(ApiError {
                    status: StatusCode::CONFLICT,
                    message: "invitation issuer or sequence conflict",
                });
            }
            if d.body.sequence == old.sequence {
                return Ok(false);
            }
        } else if self.entries.len() >= MAX_RECORDS
            || self.entries.values().filter(|r| r.grant == grant).count() >= MAX_RECORDS_PER_GRANT
        {
            return Err(ApiError {
                status: StatusCode::INSUFFICIENT_STORAGE,
                message: "invitation directory capacity reached",
            });
        }
        for entry in self.entries.values_mut() {
            if entry
                .descriptor
                .as_ref()
                .is_some_and(|d| d.body.expires_at <= now)
            {
                entry.descriptor = None;
            }
        }
        self.entries.insert(
            d.body.id.clone(),
            Entry {
                issuer: d.body.issuer_key.clone(),
                grant,
                sequence: d.body.sequence,
                retain_until: now
                    .saturating_add(gcoms_network::channel_invitation::MAX_LIFETIME + 60),
                digest: hash,
                descriptor: Some(d),
            },
        );
        Ok(true)
    }
}
fn digest(d: &Descriptor) -> Result<[u8; 32], String> {
    Ok(Sha256::digest(serde_json::to_vec(d).map_err(|_| "invalid descriptor")?).into())
}
pub(crate) async fn publish(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Json(descriptor): Json<Descriptor>,
) -> Result<StatusCode, ApiError> {
    let service = state.network.as_ref().ok_or(ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        message: "invitation directory unavailable",
    })?;
    let grant = service.authorize(&headers, "invitations")?;
    if id != descriptor.body.id || descriptor.body.network_id != service.network_id() {
        return Err(ApiError::bad("invitation network or lookup mismatch"));
    }
    let mut store = service.invitation_records.lock().await;
    let mut candidate = store.clone();
    if !candidate.stage(descriptor, grant.id, now_unix())? {
        return Ok(StatusCode::NO_CONTENT);
    }
    let bytes =
        serde_json::to_vec(&candidate).map_err(|_| ApiError::bad("invalid invitation store"))?;
    if bytes.len() > MAX_ACTIVE_BYTES {
        return Err(ApiError {
            status: StatusCode::INSUFFICIENT_STORAGE,
            message: "invitation directory byte limit reached",
        });
    }
    network::atomic_bytes(&service.invitation_path(), &bytes).map_err(internal_error)?;
    *store = candidate;
    Ok(StatusCode::NO_CONTENT)
}
pub(crate) async fn fetch(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Response, ApiError> {
    if id.len() != 22 || URL_SAFE_NO_PAD.decode(&id).is_err() {
        return Err(ApiError::bad("invalid invitation lookup"));
    }
    let service = state.network.as_ref().ok_or(ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        message: "invitation directory unavailable",
    })?;
    let store = service.invitation_records.lock().await;
    let entry = store.entries.get(&id).ok_or(ApiError {
        status: StatusCode::NOT_FOUND,
        message: "invitation owner has not published a current route",
    })?;
    service.grant_by_id(&entry.grant, "invitations")?;
    let descriptor = entry
        .descriptor
        .as_ref()
        .filter(|d| d.body.expires_at > now_unix())
        .ok_or(ApiError {
            status: StatusCode::GONE,
            message: "invitation owner is offline; retry later",
        })?;
    Ok(no_store(Json(descriptor).into_response()))
}
pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/invitations/{id}", get(fetch).put(publish))
        .layer(RequestBodyLimitLayer::new(MAX_DESCRIPTOR_BYTES))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gcoms_crypto::IdentityKeypair;
    use gcoms_network::channel_invitation::DescriptorBody;
    fn descriptor(id: u16, sequence: u64, now: u64) -> Descriptor {
        let issuer = IdentityKeypair::from_seed([81; 32]);
        let mut invitation_id = [0; 16];
        invitation_id[..2].copy_from_slice(&id.to_le_bytes());
        let body = DescriptorBody {
            version: 1,
            network_id: "test".into(),
            id: URL_SAFE_NO_PAD.encode(invitation_id),
            issuer_key: URL_SAFE_NO_PAD.encode(issuer.public_bytes()),
            sequence,
            issued_at: now,
            expires_at: now + 300,
            ciphertext: URL_SAFE_NO_PAD.encode([0; 28]),
        };
        let mut bytes = b"gcoms/invitation-descriptor/v1\0".to_vec();
        bytes.extend(serde_json::to_vec(&body).unwrap());
        Descriptor {
            body,
            signature: URL_SAFE_NO_PAD.encode(issuer.sign(&bytes)),
        }
    }
    #[test]
    fn publisher_quota_spans_channels_but_preserves_renewal_and_grant_isolation() {
        let mut store = Store::default();
        for id in 0..MAX_RECORDS_PER_GRANT as u16 {
            assert!(store
                .stage(descriptor(id, 1, 1000), "grant".into(), 1000)
                .unwrap());
        }
        let rejected = store
            .stage(
                descriptor(MAX_RECORDS_PER_GRANT as u16, 1, 1000),
                "grant".into(),
                1000,
            )
            .unwrap_err();
        assert_eq!(rejected.status, StatusCode::INSUFFICIENT_STORAGE);
        assert_eq!(rejected.message, "invitation directory capacity reached");
        assert_eq!(store.entries.len(), MAX_RECORDS_PER_GRANT);
        // A full publisher can renew or replay its existing descriptors.
        assert!(store
            .stage(descriptor(0, 2, 1001), "grant".into(), 1001)
            .unwrap());
        assert!(!store
            .stage(descriptor(0, 2, 1001), "grant".into(), 1001)
            .unwrap());
        assert_eq!(store.entries.len(), MAX_RECORDS_PER_GRANT);
        // Exhausting one scoped publisher does not consume another's quota.
        assert!(store
            .stage(
                descriptor(MAX_RECORDS_PER_GRANT as u16, 1, 1001),
                "other-grant".into(),
                1001,
            )
            .unwrap());
        assert_eq!(store.entries.len(), MAX_RECORDS_PER_GRANT + 1);
        assert!(store
            .stage(
                descriptor(MAX_RECORDS_PER_GRANT as u16 + 1, 1, 1001),
                "grant".into(),
                1001,
            )
            .is_err());
    }
    #[test]
    fn expired_records_release_quota_after_all_signed_routes_expire() {
        let mut store = Store::default();
        for id in 0..MAX_RECORDS_PER_GRANT as u16 {
            assert!(store
                .stage(descriptor(id, 2, 1000), "grant".into(), 1000)
                .unwrap());
        }
        assert!(store
            .stage(
                descriptor(MAX_RECORDS_PER_GRANT as u16, 1, 1000),
                "grant".into(),
                1000,
            )
            .is_err());
        assert!(store
            .stage(descriptor(0, 1, 1000), "grant".into(), 1001)
            .is_err());
        assert!(store
            .stage(
                descriptor(MAX_RECORDS_PER_GRANT as u16, 1, 1360),
                "grant".into(),
                1360,
            )
            .unwrap());
        assert_eq!(store.entries.len(), 1);
        assert!(store
            .stage(descriptor(0, 1, 1000), "grant".into(), 1360)
            .is_err());
    }
}
