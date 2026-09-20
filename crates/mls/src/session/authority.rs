//! Ownership follows signed delegation; channel IDs and member keys stay fixed.
use super::*;
use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer, types::SignatureScheme};

const KEY: &[u8] = b"gcoms/channel-authority/v1";
const ROOT_KEY_BYTES: usize = gcoms_crypto::IDENTITY_PK_LEN;
const ROOT_HEADER_BYTES: usize = ROOT_KEY_BYTES + 32 + 2;
const MAX_ROOT_BYTES: usize = ROOT_HEADER_BYTES + 2 + 4096;
const TRANSFER_BYTES: usize = 96;
const MAX_TRANSFERS: usize = 32;
const WELCOME_MAGIC: &[u8] = b"GCMW1";

fn root_payload(root: &[u8]) -> Vec<u8> {
    [b"gcoms/channel-authority/root/v1".as_slice(), root].concat()
}
fn transfer_payload(previous: &[u8], next: &[u8]) -> Vec<u8> {
    [
        b"gcoms/channel-authority/transfer/v1".as_slice(),
        Sha256::digest(previous).as_slice(),
        next,
    ]
    .concat()
}

fn root_size(chain: &[u8]) -> Result<usize, MlsError> {
    let size = usize::from(u16::from_be_bytes(
        chain
            .get(ROOT_HEADER_BYTES..ROOT_HEADER_BYTES + 2)
            .ok_or(MlsError::Encoding)?
            .try_into()
            .unwrap(),
    ));
    if size == 0 || size > 4096 {
        return Err(MlsError::Encoding);
    }
    let root = ROOT_HEADER_BYTES + 2 + size;
    if chain.len() < root {
        return Err(MlsError::Encoding);
    }
    Ok(root)
}

fn verify(chain: &[u8], group: &MlsGroup) -> Result<([u8; 32], usize), MlsError> {
    let root = root_size(chain)?;
    if !(chain.len() - root).is_multiple_of(TRANSFER_BYTES)
        || chain.len() > root + MAX_TRANSFERS * TRANSFER_BYTES
    {
        return Err(MlsError::Encoding);
    }
    if channel_group_id(&chain[..ROOT_KEY_BYTES]).as_slice() != group.group_id().as_slice()
        || !gcoms_crypto::verify_signature(
            &chain[..ROOT_KEY_BYTES],
            &root_payload(&chain[..ROOT_HEADER_BYTES]),
            &chain[ROOT_HEADER_BYTES + 2..root],
        )
    {
        return Err(MlsError::Unauthorized);
    }
    let capacity = usize::from(u16::from_be_bytes(
        chain[ROOT_HEADER_BYTES - 2..ROOT_HEADER_BYTES]
            .try_into()
            .unwrap(),
    ));
    if !(2..=CHANNEL_MAX).contains(&capacity) {
        return Err(MlsError::Encoding);
    }
    let mut owner: [u8; 32] = chain[ROOT_KEY_BYTES..ROOT_KEY_BYTES + 32]
        .try_into()
        .unwrap();
    let crypto = OpenMlsRustCrypto::default();
    for start in (root..chain.len()).step_by(TRANSFER_BYTES) {
        let next: [u8; 32] = chain[start..start + 32].try_into().unwrap();
        if next == owner
            || crypto
                .crypto()
                .verify_signature(
                    SignatureScheme::ED25519,
                    &transfer_payload(&chain[..start], &next),
                    &owner,
                    &chain[start + 32..start + 96],
                )
                .is_err()
        {
            return Err(MlsError::Unauthorized);
        }
        owner = next;
    }
    if !group.members().any(|m| m.signature_key.as_slice() == owner) {
        return Err(MlsError::MemberNotFound);
    }
    Ok((owner, capacity))
}

impl Ctx {
    fn install_owner_from(&mut self, actor: [u8; 32], chain: &[u8]) -> Result<(), MlsError> {
        let (next, _) = verify(chain, &self.group)?;
        if self.owner_pseudonym != Some(actor) && next != actor {
            return Err(MlsError::Unauthorized);
        }
        self.install_owner(chain)
    }
    fn authority_chain(&self) -> Result<Vec<u8>, MlsError> {
        let storage = self
            .backend
            .storage()
            .values
            .read()
            .map_err(|_| MlsError::Encoding)?;
        Ok(storage.get(KEY).cloned().unwrap_or_default())
    }
    fn store_authority(&mut self, chain: Vec<u8>, owner: [u8; 32]) -> Result<(), MlsError> {
        self.backend
            .storage()
            .values
            .write()
            .map_err(|_| MlsError::Encoding)?
            .insert(KEY.to_vec(), chain);
        self.owner_pseudonym = Some(owner);
        self.admin_pseudonyms.clear();
        Ok(())
    }
    fn propose_owner(&self, next: [u8; 32]) -> Result<Vec<u8>, MlsError> {
        if self.owner_pseudonym != Some(self.own_pseudonym()) || next == self.own_pseudonym() {
            return Err(MlsError::Unauthorized);
        }
        let mut chain = self.authority_chain()?;
        let (owner, _) = verify(&chain, &self.group)?;
        if Some(owner) != self.owner_pseudonym
            || chain.len() >= root_size(&chain)? + MAX_TRANSFERS * TRANSFER_BYTES
        {
            return Err(MlsError::Unauthorized);
        }
        let signature = self
            .signer
            .sign(&transfer_payload(&chain, &next))
            .map_err(|_| MlsError::Encoding)?;
        chain.extend(next);
        chain.extend(signature);
        verify(&chain, &self.group)?;
        Ok(chain)
    }
    fn install_owner(&mut self, chain: &[u8]) -> Result<(), MlsError> {
        let (owner, _) = verify(chain, &self.group)?;
        let previous = self.authority_chain()?;
        if previous == chain {
            return Ok(());
        }
        if previous.is_empty() {
            if chain.len() != root_size(chain)? + TRANSFER_BYTES
                || self.owner_pseudonym.as_ref().map(|p| p.as_slice())
                    != Some(&chain[ROOT_KEY_BYTES..ROOT_KEY_BYTES + 32])
            {
                return Err(MlsError::Unauthorized);
            }
        } else if chain.len() != previous.len() + TRANSFER_BYTES || !chain.starts_with(&previous) {
            return Err(MlsError::Unauthorized);
        }
        self.store_authority(chain.to_vec(), owner)
    }
    pub(super) fn wrap_welcome(&self, welcome: Vec<u8>) -> Result<Vec<u8>, MlsError> {
        let chain = self.authority_chain()?;
        if chain.is_empty() {
            return Ok(welcome);
        }
        let size = u16::try_from(chain.len()).map_err(|_| MlsError::Encoding)?;
        Ok([WELCOME_MAGIC, &size.to_be_bytes(), &chain, &welcome].concat())
    }
}

pub(super) fn split_welcome(welcome: &[u8]) -> Result<(&[u8], Option<&[u8]>), MlsError> {
    if !welcome.starts_with(WELCOME_MAGIC) {
        return Ok((welcome, None));
    }
    let size = usize::from(u16::from_be_bytes(
        welcome
            .get(5..7)
            .ok_or(MlsError::Encoding)?
            .try_into()
            .unwrap(),
    ));
    if size > MAX_ROOT_BYTES + MAX_TRANSFERS * TRANSFER_BYTES {
        return Err(MlsError::Encoding);
    }
    Ok((
        welcome.get(7 + size..).ok_or(MlsError::Encoding)?,
        Some(welcome.get(7..7 + size).ok_or(MlsError::Encoding)?),
    ))
}

pub(super) fn restore_join_authority(
    member: &mut ChannelMember,
    chain: Option<&[u8]>,
) -> Result<(), MlsError> {
    if let Some(chain) = chain {
        let (owner, _) = verify(chain, &member.ctx.group)?;
        member.ctx.store_authority(chain.to_vec(), owner)?;
    }
    Ok(())
}

impl OwnerSession {
    pub fn ownership_certificate(&self) -> Result<Vec<u8>, MlsError> {
        self.ctx.authority_chain()
    }
    pub fn install_owner_from(&mut self, actor: [u8; 32], chain: &[u8]) -> Result<(), MlsError> {
        self.ctx.install_owner_from(actor, chain)
    }
    pub fn propose_owner(&mut self, next: [u8; 32]) -> Result<Vec<u8>, MlsError> {
        if self.ctx.authority_chain()?.is_empty() {
            if self.ctx.owner_pseudonym != Some(self.ctx.own_pseudonym()) {
                return Err(MlsError::Unauthorized);
            }
            let mut root = self.identity.public_bytes();
            root.extend(self.ctx.own_pseudonym());
            root.extend(
                u16::try_from(self.capacity)
                    .map_err(|_| MlsError::Encoding)?
                    .to_be_bytes(),
            );
            let signature = self.identity.sign(&root_payload(&root));
            root.extend(
                u16::try_from(signature.len())
                    .map_err(|_| MlsError::Encoding)?
                    .to_be_bytes(),
            );
            root.extend(signature);
            self.ctx.store_authority(root, self.ctx.own_pseudonym())?;
        }
        self.ctx.propose_owner(next)
    }
    pub fn install_owner(&mut self, chain: &[u8]) -> Result<(), MlsError> {
        self.ctx.install_owner(chain)
    }
}
impl ChannelMember {
    pub fn ownership_certificate(&self) -> Result<Vec<u8>, MlsError> {
        self.ctx.authority_chain()
    }
    pub fn install_owner_from(&mut self, actor: [u8; 32], chain: &[u8]) -> Result<(), MlsError> {
        self.ctx.install_owner_from(actor, chain)
    }
    pub fn propose_owner(&mut self, next: [u8; 32]) -> Result<Vec<u8>, MlsError> {
        self.ctx.propose_owner(next)
    }
    pub fn install_owner(&mut self, chain: &[u8]) -> Result<(), MlsError> {
        self.ctx.install_owner(chain)
    }
    /// Admission by the current delegated owner; the existing group identity
    /// and root-bound capacity are retained in the newcomer's Welcome.
    pub fn stage_admit_current(
        &mut self,
        package: &[u8],
        name: &str,
    ) -> Result<StagedAdmission, MlsError> {
        let (_, capacity) = verify(&self.ctx.authority_chain()?, &self.ctx.group)?;
        self.ctx.stage_admit(package, name, capacity)
    }
    pub fn stage_remove_current(&mut self, member: [u8; 32]) -> Result<StagedRemoval, MlsError> {
        self.ctx.stage_remove(member)
    }
    pub fn merge_pending(&mut self) -> Result<(), MlsError> {
        self.ctx
            .group
            .merge_pending_commit(&self.ctx.backend)
            .map_err(|e| MlsError::OpenMls(format!("{e:?}")))
    }
}

#[cfg(all(test, feature = "client-persist"))]
mod tests {
    use super::*;

    #[test]
    fn ownership_transfer_keeps_channel_and_newcomer_authority_after_creator_leaves() {
        let mut owner =
            OwnerSession::create(IdentityKeypair::from_seed([83; 32]), "original", 8).unwrap();
        let join = ChannelMember::prepare("next").unwrap();
        let package = ChannelMember::key_package_bytes(&join).unwrap();
        let invite = owner.sign_invite_key_package(&package, "next", crate::Caps::member(), 3600);
        let admission = owner.admit(&invite, &package).unwrap();
        let mut next = ChannelMember::join(join, &admission.welcome).unwrap();
        let channel = next.stable_channel_id();
        let original = owner.own_pseudonym();
        let successor = next.own_pseudonym();
        assert!(next.propose_owner(original).is_err());
        let delegation = owner.propose_owner(successor).unwrap();
        let mut forged = delegation.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(next.install_owner(&forged).is_err());
        assert_eq!(next.channel_owner(), Some(original));
        owner.install_owner(&delegation).unwrap();
        next.install_owner(&delegation).unwrap();
        assert_eq!(owner.channel_owner(), Some(successor));
        assert!(owner.stage_remove(successor).is_err());
        let staged = next.stage_remove_current(original).unwrap();
        next.merge_pending().unwrap();
        assert!(matches!(
            owner.receive_outcome(&staged.commit),
            Err(MlsError::Removed)
        ));
        let saved = next.persist(&[14; 32]).unwrap();
        let mut next = ChannelMember::restore(&[14; 32], &saved).unwrap();
        assert_eq!(next.channel_owner(), Some(successor));
        let join = ChannelMember::prepare("newcomer").unwrap();
        let package = ChannelMember::key_package_bytes(&join).unwrap();
        let admission = next.stage_admit_current(&package, "newcomer").unwrap();
        next.merge_pending().unwrap();
        let mut newcomer = ChannelMember::join(join, &admission.welcome).unwrap();
        assert_eq!(newcomer.stable_channel_id(), channel);
        assert_eq!(newcomer.channel_owner(), Some(successor));
        assert!(newcomer.stage_remove_current(successor).is_err());
        let wire = next.send(b"same channel after handoff").unwrap();
        assert!(
            matches!(newcomer.receive_outcome(&wire), Ok(ReceiveOutcome::Application { payload, .. }) if payload == b"same channel after handoff")
        );
    }
}
