//! Route selection does not mint a nonce or start the short hop-authority
//! lifetime. Encoding happens only after the transport has admitted the request.
use super::*;

pub(super) struct PendingRequest {
    pub target: RelayTarget,
    pub token: String,
    pub excluded: Vec<(SocketAddr, [u8; 32])>,
    pub subscription: bool,
    pub make: Box<dyn FnOnce() -> Result<bytes::Bytes, String> + Send>,
}

impl PendingRequest {
    pub fn semantic(semantic: SemanticJob, round: u16, seed: [u8; 32]) -> Result<Self, String> {
        let (target, token, excluded, subscription) = match &semantic {
            SemanticJob::Push { contact, .. } => (
                contact.target.clone(),
                gcoms_transport::encode_b64url(&contact.queue_id),
                Vec::new(),
                false,
            ),
            SemanticJob::Frwd {
                relay, destination, ..
            } => (
                relay
                    .aliases
                    .first()
                    .ok_or("client relay provision has no target")?
                    .contact
                    .target
                    .clone(),
                relay.frwd_path.clone(),
                vec![(
                    destination.target.address,
                    destination.target.relay_service_id,
                )],
                false,
            ),
            SemanticJob::Forward { target, push } => (
                target.clone(),
                gcoms_transport::encode_b64url(&push.queue_id()),
                Vec::new(),
                false,
            ),
            SemanticJob::AdminPost { target, token, .. } => {
                (target.clone(), token.clone(), Vec::new(), false)
            }
            SemanticJob::Subscribe(alias) => (
                alias.contact.target.clone(),
                gcoms_transport::encode_b64url(&alias.contact.queue_id),
                Vec::new(),
                true,
            ),
        };
        Ok(Self::new(
            target,
            token,
            excluded,
            subscription,
            move || prepare(semantic, round, &mut StdRng::from_seed(seed)),
        ))
    }

    pub fn cover(auth: LaneAuth, round: u16, seed: [u8; 32]) -> Self {
        let key = auth.key();
        let excluded = match &auth {
            LaneAuth::Frwd { decoy_target, .. } => {
                vec![(decoy_target.address, decoy_target.relay_service_id)]
            }
            _ => Vec::new(),
        };
        Self::new(
            RelayTarget {
                address: key.address,
                relay_service_id: key.service_id,
            },
            key.token,
            excluded,
            false,
            move || auth.cover_request(round, &mut StdRng::from_seed(seed)),
        )
    }

    fn new(
        target: RelayTarget,
        token: String,
        excluded: Vec<(SocketAddr, [u8; 32])>,
        subscription: bool,
        prepare: impl FnOnce() -> Result<Request, String> + Send + 'static,
    ) -> Self {
        // Keep the admitted pinned route and the authenticated envelope bound
        // even if a future encoder changes its routing decisions.
        let expected_target = target.clone();
        let expected_token = token.clone();
        let expected_excluded = excluded.clone();
        let make = Box::new(move || {
            let (actual_target, actual_token, actual_excluded, actual_sub, wire) = match prepare()?
            {
                Request::Post {
                    target,
                    token,
                    excluded,
                    wire,
                } => (target, token, excluded, false, wire),
                Request::Subscribe { alias, auth } => (
                    alias.contact.target.clone(),
                    gcoms_transport::encode_b64url(&alias.contact.queue_id),
                    Vec::new(),
                    true,
                    auth,
                ),
            };
            if actual_target != expected_target
                || actual_token != expected_token
                || actual_excluded != expected_excluded
                || actual_sub != subscription
            {
                return Err("prepared request changed its admitted route".into());
            }
            Ok(bytes::Bytes::from(wire))
        });
        Self {
            target,
            token,
            excluded,
            subscription,
            make,
        }
    }
}
