use super::*;

const REKEY: &[u8] = b"gcoms/hosted/rekey/v1";

fn rekey_aad(revision: u64) -> Vec<u8> {
    let mut aad = REKEY.to_vec();
    aad.extend_from_slice(&revision.to_be_bytes());
    aad
}

pub(super) fn used_invitation(processed: &ProcessedMessage) -> Result<Option<[u8; 32]>, MlsError> {
    if matches!(processed.sender(), Sender::NewMemberCommit) {
        let permit = JoinPermit::decode(processed.aad())?;
        Ok((permit.authority == 3).then_some(permit.issuer).flatten())
    } else {
        Ok(None)
    }
}

pub(super) fn validate_membership(
    policy: &HostedPolicy,
    rules: &HostedRules,
    members: impl Iterator<Item = Member>,
    processed: &ProcessedMessage,
    now: u64,
) -> Result<Vec<[u8; 32]>, MlsError> {
    if rules.closed() {
        return Err(MlsError::Unauthorized);
    }
    let ProcessedMessageContent::StagedCommitMessage(commit) = processed.content() else {
        return Err(MlsError::Unauthorized);
    };
    let members: Vec<_> = members.collect();
    let mut removed = Vec::new();
    for proposal in commit.queued_proposals() {
        match proposal.proposal() {
            Proposal::Remove(remove) => {
                let member = members
                    .iter()
                    .find(|m| m.index == remove.removed())
                    .ok_or(MlsError::MemberNotFound)?;
                let key: [u8; 32] = member
                    .signature_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| MlsError::Encoding)?;
                if !rules.departing(key) || removed.contains(&key) {
                    return Err(MlsError::Unauthorized);
                }
                removed.push(key);
            }
            Proposal::ExternalInit(_) if matches!(processed.sender(), Sender::NewMemberCommit) => {}
            _ => return Err(MlsError::Unauthorized),
        }
    }
    match processed.sender() {
        Sender::Member(index) => {
            let actor = members
                .iter()
                .find(|m| m.index == *index)
                .ok_or(MlsError::MemberNotFound)?;
            let key = actor
                .signature_key
                .as_slice()
                .try_into()
                .map_err(|_| MlsError::Encoding)?;
            // Only the already-authorized set may be committed. No arbitrary
            // removal, privilege escalation or stale policy context is allowed.
            removed.sort_unstable();
            if rules.departing(key)
                || rules.banned(key)
                || removed.is_empty()
                || removed != rules.pending_removals()
                || processed.aad() != rekey_aad(rules.revision())
                || commit.update_path_leaf_node().is_none_or(|leaf| {
                    leaf.signature_key().as_slice() != actor.signature_key
                        || leaf.credential() != &actor.credential
                })
            {
                return Err(MlsError::Unauthorized);
            }
        }
        Sender::NewMemberCommit => {
            let leaf = commit
                .update_path_leaf_node()
                .ok_or(MlsError::Unauthorized)?;
            let key: [u8; 32] = leaf
                .signature_key()
                .as_slice()
                .try_into()
                .map_err(|_| MlsError::Encoding)?;
            // MLS external rejoin may replace this identity's old leaf only
            // after it has left or been kicked. It cannot remove other members.
            if removed.iter().any(|id| *id != key) {
                return Err(MlsError::Unauthorized);
            }
            let mut active = 0;
            for member in &members {
                let id = member
                    .signature_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| MlsError::Encoding)?;
                if !rules.departing(id) {
                    active += 1;
                }
                if !removed.contains(&id)
                    && (member.credential.serialized_content()
                        == leaf.credential().serialized_content()
                        || member.signature_key.as_slice() == key)
                {
                    return Err(MlsError::BadInvite);
                }
            }
            if active >= rules.capacity() as usize
                || members.len().saturating_sub(removed.len()) >= 1000
            {
                return Err(MlsError::GroupFull);
            }
            policy.authorize(
                rules,
                processed.epoch().as_u64(),
                &key,
                leaf.credential().serialized_content(),
                processed.aad(),
                now,
            )?;
        }
        _ => return Err(MlsError::Unauthorized),
    }
    Ok(removed)
}

impl HostedSession {
    pub fn member_id(&self) -> [u8; 32] {
        self.ctx
            .signer
            .public()
            .try_into()
            .expect("Ed25519 key length")
    }

    pub fn active(&self) -> bool {
        self.pending_join.is_none()
            && self.ctx.group.is_active()
            && !self.rules.departing(self.member_id())
            && !self.rules.closed()
    }

    /// Retain the channel-scoped identity when rejoining after departure. The
    /// caller retains the old archive until the new admission is durable.
    pub fn prepare_rejoin(&self, name: &str) -> Result<PreparedHostedJoin, MlsError> {
        if self.pending_join.is_some() || self.active() || !valid_name(name.as_bytes()) {
            return Err(MlsError::Unauthorized);
        }
        let encoded = zeroize::Zeroizing::new(self.ctx.signer.tls_serialize_detached()?);
        let signer = SignatureKeyPair::tls_deserialize_exact(encoded.as_slice())?;
        let backend = OpenMlsRustCrypto::default();
        signer.store(backend.storage()).map_err(mls)?;
        Ok(PreparedHostedJoin {
            credential: CredentialWithKey {
                credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
                signature_key: SignaturePublicKey::from(signer.to_public_vec()),
            },
            backend,
            signer: Some(signer),
        })
    }

    /// Prepare removal of exactly the departed members. Any remaining member
    /// can perform this work, including a newly admitted member while the owner
    /// is offline. Persist this state and exact wire before submitting it.
    pub fn prepare_rekey(&mut self) -> Result<Vec<u8>, MlsError> {
        if !self.active()
            || self.pending_rekey.is_some()
            || self.rules.banned(self.member_id())
            || self.rules.pending_removals().is_empty()
        {
            return Err(MlsError::Unauthorized);
        }
        let mut candidate = self.fork()?;
        let indices: Vec<_> = candidate
            .ctx
            .group
            .members()
            .filter(|member| {
                candidate.rules.departing(
                    member
                        .signature_key
                        .as_slice()
                        .try_into()
                        .expect("Ed25519 key"),
                )
            })
            .map(|member| member.index)
            .collect();
        candidate
            .ctx
            .group
            .set_aad(rekey_aad(candidate.rules.revision()));
        let (commit, _, info) = candidate
            .ctx
            .group
            .remove_members(&candidate.ctx.backend, &candidate.ctx.signer, &indices)
            .map_err(mls)?;
        let commit = commit.tls_serialize_detached()?;
        let info: MlsMessageOut = info.ok_or(MlsError::Encoding)?.into();
        candidate.pending_rekey = Some(PendingJoin {
            hash: Sha256::digest(&commit).into(),
            info: info.tls_serialize_detached()?,
        });
        *self = candidate;
        Ok(commit)
    }

    /// Merge only after the ordered service accepted this exact commit.
    pub fn accept_rekey(&mut self, accepted_commit: &[u8]) -> Result<(), MlsError> {
        if self.pending_rekey.as_ref().map(|p| p.hash)
            != Some(Sha256::digest(accepted_commit).into())
        {
            return Err(MlsError::Unauthorized);
        }
        let mut candidate = self.fork()?;
        candidate
            .ctx
            .group
            .merge_pending_commit(&candidate.ctx.backend)
            .map_err(mls)?;
        let removed = candidate.rules.pending_removals().to_vec();
        candidate.rules.finish_removals(&removed);
        candidate.pending_rekey = None;
        *self = candidate;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modified_member_cannot_invent_removal_or_rekey_with_stale_policy() {
        let root = IdentityKeypair::from_seed([98; 32]);
        let mut owner = HostedSession::create(&root, "owner", 500, true).unwrap();
        let mut public = HostedObserver::new(
            owner.policy.clone(),
            owner.policy.channel_id(),
            &owner.export_group_info().unwrap(),
        )
        .unwrap();
        let (mut alice, commit) = PreparedHostedJoin::new("alice")
            .unwrap()
            .join(&public, &JoinPermit::public(), 100)
            .unwrap();
        public = public
            .stage_join(&commit, alice.proposed_group_info().unwrap(), 100)
            .unwrap();
        alice.accept_join(&commit).unwrap();
        owner.receive(&commit, 100).unwrap();
        let (mut bob, commit) = PreparedHostedJoin::new("bob")
            .unwrap()
            .join(&public, &JoinPermit::public(), 100)
            .unwrap();
        public = public
            .stage_join(&commit, bob.proposed_group_info().unwrap(), 100)
            .unwrap();
        bob.accept_join(&commit).unwrap();
        owner.receive(&commit, 100).unwrap();
        alice.receive(&commit, 100).unwrap();
        let target = alice
            .ctx
            .group
            .members()
            .find(|m| m.signature_key.as_slice() == bob.member_id())
            .unwrap()
            .index;
        let forge = |alice: &HostedSession, revision| {
            let mut modified = alice.fork().unwrap();
            modified.ctx.group.set_aad(rekey_aad(revision));
            let (commit, _, info) = modified
                .ctx
                .group
                .remove_members(&modified.ctx.backend, &modified.ctx.signer, &[target])
                .unwrap();
            let info: MlsMessageOut = info.unwrap().into();
            (
                commit.tls_serialize_detached().unwrap(),
                info.tls_serialize_detached().unwrap(),
            )
        };
        let (commit, info) = forge(&alice, 0);
        assert!(public.stage_join(&commit, &info, 100).is_err());
        assert!(owner.receive(&commit, 100).is_err());
        assert!(bob.receive(&commit, 100).is_err());
        assert!(bob.active());
        let kick = owner
            .create_control(HostedPolicyChange::Kick(bob.member_id()), "authorized")
            .unwrap();
        public = public.stage_control(&kick).unwrap();
        owner.apply_control(&kick).unwrap();
        alice.apply_control(&kick).unwrap();
        bob.apply_control(&kick).unwrap();
        let (stale, info) = forge(&alice, 0);
        assert!(public.stage_join(&stale, &info, 100).is_err());
        assert!(owner.receive(&stale, 100).is_err());
        let accepted = alice.prepare_rekey().unwrap();
        public = public
            .stage_join(&accepted, alice.proposed_group_info().unwrap(), 100)
            .unwrap();
        alice.accept_rekey(&accepted).unwrap();
        owner.receive(&accepted, 100).unwrap();
        let epoch = bob.epoch();
        let previous_info = bob.export_group_info().unwrap();
        assert!(bob
            .receive_membership(&accepted, &previous_info, 100)
            .is_err());
        assert_eq!(
            bob.epoch(),
            epoch,
            "invalid snapshots must not mutate state"
        );
        assert!(matches!(
            bob.receive_membership(&accepted, &alice.export_group_info().unwrap(), 100),
            Err(MlsError::Removed)
        ));
        assert!(!bob.active());
        assert_eq!(public.member_count(), 2);
        assert_eq!(owner.epoch(), alice.epoch());
    }
}
