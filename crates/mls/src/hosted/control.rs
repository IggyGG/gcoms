use super::*;

const DOMAIN: &[u8] = b"gcoms/hosted/control/v1";
const DETAIL: &[u8] = b"gcoms/hosted/control-detail/v1";
const MAX_CONTROL: usize = 16 * 1024;

/// Signed public policy change with an MLS-encrypted reason. The service can
/// enforce authority and ordering without learning the human-readable reason.
#[derive(Clone, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct HostedControl {
    channel: [u8; 32],
    epoch: u64,
    context: [u8; 32],
    base_revision: u64,
    actor: [u8; 32],
    change: HostedPolicyChange,
    detail: VLBytes,
    signature: VLBytes,
}

#[derive(Clone, Debug)]
pub struct HostedControlEvent {
    pub actor: [u8; 32],
    pub revision: u64,
    pub change: HostedPolicyChange,
    /// Incoming authenticated reason. The sender uses its durable outgoing
    /// operation's original text, since MLS does not decrypt its own sends.
    pub reason: Option<String>,
}

impl HostedControl {
    pub fn encode(&self) -> Result<Vec<u8>, MlsError> {
        Ok(self.tls_serialize_detached()?)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, MlsError> {
        if bytes.len() > MAX_CONTROL {
            return Err(MlsError::Encoding);
        }
        Ok(Self::tls_deserialize_exact(bytes)?)
    }
    pub fn actor(&self) -> [u8; 32] {
        self.actor
    }
    pub fn change(&self) -> &HostedPolicyChange {
        &self.change
    }
    pub fn base_revision(&self) -> u64 {
        self.base_revision
    }
    fn payload(&self) -> Result<Vec<u8>, MlsError> {
        let mut bytes = DOMAIN.to_vec();
        bytes.extend_from_slice(&self.channel);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.context);
        bytes.extend_from_slice(&self.base_revision.to_be_bytes());
        bytes.extend_from_slice(&self.actor);
        bytes.extend_from_slice(&self.change.tls_serialize_detached()?);
        bytes.extend_from_slice(&Sha256::digest(self.detail.as_slice()));
        Ok(bytes)
    }
    fn validate(
        &self,
        policy: &HostedPolicy,
        rules: &HostedRules,
        context: &GroupContext,
        members: &[Member],
        backend: &OpenMlsRustCrypto,
    ) -> Result<HostedRules, MlsError> {
        if self.channel != policy.channel_id() {
            return Err(MlsError::WrongChannel);
        }
        let epoch = context.epoch().as_u64();
        if self.epoch != epoch || self.base_revision != rules.revision() {
            return Err(MlsError::StaleState);
        }
        if self.context != <[u8; 32]>::from(Sha256::digest(context.tls_serialize_detached()?))
            || self.tls_serialized_len() > MAX_CONTROL
        {
            return Err(MlsError::Unauthorized);
        }
        let protocol = protocol(self.detail.as_slice())?;
        if !matches!(protocol, ProtocolMessage::PrivateMessage(_))
            || protocol.content_type() != ContentType::Application
            || protocol.epoch().as_u64() != epoch
            || protocol.group_id().as_slice() != self.channel
        {
            return Err(MlsError::Unauthorized);
        }
        backend
            .crypto()
            .verify_signature(
                CIPHERSUITE.signature_algorithm(),
                &self.payload()?,
                &self.actor,
                self.signature.as_slice(),
            )
            .map_err(|_| MlsError::Unauthorized)?;
        rules.transition(self.actor, &self.change, members)
    }
}

impl HostedSession {
    /// Prepare a control record. Persist the advanced sender state and outgoing
    /// operation before transport; apply only after ordered service acceptance.
    pub fn create_control(
        &mut self,
        change: HostedPolicyChange,
        reason: &str,
    ) -> Result<HostedControl, MlsError> {
        if self.pending_join.is_some() || reason.len() > 512 || reason.contains('\0') {
            return Err(MlsError::Unauthorized);
        }
        let actor = self
            .ctx
            .signer
            .to_public_vec()
            .try_into()
            .map_err(|_| MlsError::Encoding)?;
        self.rules.transition(
            actor,
            &change,
            &self.ctx.group.members().collect::<Vec<_>>(),
        )?;
        let mut detail = DETAIL.to_vec();
        detail.extend_from_slice(reason.as_bytes());
        let detail = self
            .ctx
            .group
            .create_message(&self.ctx.backend, &self.ctx.signer, &detail)
            .map_err(mls)?
            .tls_serialize_detached()?;
        let mut control = HostedControl {
            channel: self.policy.channel_id(),
            epoch: self.epoch(),
            context: Sha256::digest(
                self.ctx
                    .group
                    .public_group()
                    .group_context()
                    .tls_serialize_detached()?,
            )
            .into(),
            base_revision: self.rules.revision(),
            actor,
            change,
            detail: detail.into(),
            signature: Vec::new().into(),
        };
        control.signature = self
            .ctx
            .signer
            .sign(&control.payload()?)
            .map_err(mls)?
            .into();
        Ok(control)
    }

    pub fn apply_control(
        &mut self,
        control: &HostedControl,
    ) -> Result<HostedControlEvent, MlsError> {
        if self.pending_join.is_some() {
            return Err(MlsError::Unauthorized);
        }
        let rules = control.validate(
            &self.policy,
            &self.rules,
            self.ctx.group.public_group().group_context(),
            &self.ctx.group.members().collect::<Vec<_>>(),
            &self.ctx.backend,
        )?;
        // Policy authority is independently authenticated. An unreadable or
        // falsely attributed optional reason must not fork the policy state.
        let reason = if control.actor.as_slice() == self.ctx.signer.public() {
            None
        } else {
            self.control_reason(control).ok()
        };
        self.rules = rules;
        Ok(HostedControlEvent {
            actor: control.actor,
            revision: self.rules.revision(),
            change: control.change.clone(),
            reason,
        })
    }
    fn control_reason(&mut self, control: &HostedControl) -> Result<String, MlsError> {
        let mut candidate = self.fork()?;
        let processed = candidate
            .ctx
            .group
            .process_message(&candidate.ctx.backend, protocol(control.detail.as_slice())?)
            .map_err(mls)?;
        let Sender::Member(index) = processed.sender() else {
            return Err(MlsError::Unauthorized);
        };
        if !candidate
            .ctx
            .group
            .members()
            .any(|m| m.index == *index && m.signature_key.as_slice() == control.actor)
        {
            return Err(MlsError::Unauthorized);
        }
        let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content() else {
            return Err(MlsError::Unauthorized);
        };
        let payload = message.into_bytes();
        let text = payload.strip_prefix(DETAIL).ok_or(MlsError::Encoding)?;
        if text.len() > 512 || text.contains(&0) {
            return Err(MlsError::Encoding);
        }
        let reason = std::str::from_utf8(text)
            .map_err(|_| MlsError::Encoding)?
            .to_owned();
        *self = candidate;
        Ok(reason)
    }
}

impl HostedObserver {
    /// Replay an authenticated public control between commits without requiring
    /// an intermediate GroupInfo snapshot at each epoch.
    pub fn replay_control(&mut self, control: &HostedControl) -> Result<(), MlsError> {
        let rules = control.validate(
            &self.policy,
            &self.rules,
            self.group.group_context(),
            &self.group.members().collect::<Vec<_>>(),
            &self.backend,
        )?;
        self.rules = rules;
        Ok(())
    }

    pub fn stage_control(&self, control: &HostedControl) -> Result<Self, MlsError> {
        let rules = control.validate(
            &self.policy,
            &self.rules,
            self.group.group_context(),
            &self.group.members().collect::<Vec<_>>(),
            &self.backend,
        )?;
        let mut next = Self::from_info(self.policy.clone(), &self.info)?;
        next.rules = rules;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modified_member_cannot_grant_roles_or_impersonate_owner() {
        let root = IdentityKeypair::from_seed([31; 32]);
        let mut owner = HostedSession::create(&root, "owner", 500, true).unwrap();
        let public = HostedObserver::new(
            owner.policy.clone(),
            owner.policy.channel_id(),
            &owner.export_group_info().unwrap(),
        )
        .unwrap();
        let prepared = PreparedHostedJoin::new("alice").unwrap();
        let alice_id = prepared.member_id();
        let (mut alice, join) = prepared.join(&public, &JoinPermit::public(), 100).unwrap();
        let public = public
            .stage_join(&join, alice.proposed_group_info().unwrap(), 100)
            .unwrap();
        alice.accept_join(&join).unwrap();
        owner.receive(&join, 100).unwrap();
        let mut forged = owner
            .create_control(
                HostedPolicyChange::Role(alice_id, HostedRole::Operator),
                "promotion",
            )
            .unwrap();
        forged.actor = alice_id;
        forged.signature = alice
            .ctx
            .signer
            .sign(&forged.payload().unwrap())
            .unwrap()
            .into();
        assert!(public.stage_control(&forged).is_err());
        assert!(owner.apply_control(&forged).is_err());
        assert_eq!(owner.rules.revision(), 0);
        assert_eq!(public.rules.revision(), 0);
        forged.actor = owner.rules.owner();
        forged.signature = alice
            .ctx
            .signer
            .sign(&forged.payload().unwrap())
            .unwrap()
            .into();
        assert!(public.stage_control(&forged).is_err());
        assert!(owner.apply_control(&forged).is_err());
    }

    #[test]
    fn bad_optional_reason_cannot_fork_policy_or_consume_chat() {
        let root = IdentityKeypair::from_seed([32; 32]);
        let mut owner = HostedSession::create(&root, "owner", 500, true).unwrap();
        let mut public = HostedObserver::new(
            owner.policy.clone(),
            owner.policy.channel_id(),
            &owner.export_group_info().unwrap(),
        )
        .unwrap();
        let prepared = PreparedHostedJoin::new("alice").unwrap();
        let alice_id = prepared.member_id();
        let (mut alice, join) = prepared.join(&public, &JoinPermit::public(), 100).unwrap();
        public = public
            .stage_join(&join, alice.proposed_group_info().unwrap(), 100)
            .unwrap();
        alice.accept_join(&join).unwrap();
        owner.receive(&join, 100).unwrap();
        let grant = owner
            .create_control(
                HostedPolicyChange::Role(alice_id, HostedRole::Operator),
                "operator",
            )
            .unwrap();
        public = public.stage_control(&grant).unwrap();
        owner.apply_control(&grant).unwrap();
        alice.apply_control(&grant).unwrap();
        let original = alice.send_hosted(b"actual chat, not a reason").unwrap();
        let mut control = alice
            .create_control(
                HostedPolicyChange::Discovery(HostedDiscovery::Secret),
                "ignored",
            )
            .unwrap();
        control.detail = original.ciphertext.clone();
        control.signature = alice
            .ctx
            .signer
            .sign(&control.payload().unwrap())
            .unwrap()
            .into();
        public = public.stage_control(&control).unwrap();
        assert!(owner.apply_control(&control).unwrap().reason.is_none());
        alice.apply_control(&control).unwrap();
        assert_eq!(owner.rules.discovery(), HostedDiscovery::Secret);
        assert_eq!(owner.rules.revision(), public.rules.revision());
        assert_eq!(
            owner.receive_hosted(&original).unwrap(),
            b"actual chat, not a reason"
        );
        assert!(
            public.stage_control(&control).is_err(),
            "control replay is refused"
        );
        let mut escalation = alice
            .create_control(
                HostedPolicyChange::Discovery(HostedDiscovery::Private),
                "change",
            )
            .unwrap();
        escalation.change = HostedPolicyChange::Transfer(alice_id);
        escalation.signature = alice
            .ctx
            .signer
            .sign(&escalation.payload().unwrap())
            .unwrap()
            .into();
        assert!(public.stage_control(&escalation).is_err());
        assert!(owner.apply_control(&escalation).is_err());
    }
}
