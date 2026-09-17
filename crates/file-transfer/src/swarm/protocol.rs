use super::{Error, Result};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CONTENT_TYPE: &str = gcoms_core::PIECE_CONTENT_TYPE;
pub const PIECE_BYTES: usize = 256 * 1024;
pub const BLOCK_BYTES: usize = 11 * 1024;
pub const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024 * 1024;
pub const MAX_PIECES: usize = (MAX_FILE_BYTES / PIECE_BYTES as u64) as usize;
pub const MAX_TRANSFERS: usize = 256;
pub const INVENTORY_PAGE: usize = 256;
pub type ShareId = [u8; 16];
pub type Hash = [u8; 32];
pub type Member = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub channel: [u8; 32],
    /// Empty means all current channel members; two sorted identities mean a PM.
    pub participants: Vec<Member>,
}
impl Scope {
    pub fn validate(&self) -> Result<()> {
        if !self.participants.is_empty()
            && (self.participants.len() != 2 || self.participants[0] >= self.participants[1])
        {
            return Err(Error::Invalid("conversation scope"));
        }
        Ok(())
    }
    pub fn permits(&self, member: &Member) -> bool {
        self.participants.is_empty() || self.participants.contains(member)
    }
}

/// This descriptor contains the content key. Transmit only within authenticated,
/// encrypted conversations and retain only in the host-encrypted cache journal.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u8,
    pub id: ShareId,
    pub scope: Scope,
    pub name: String,
    pub size: u64,
    pub sha256: Hash,
    pub root: Hash,
    pub key: [u8; 32],
}
impl std::fmt::Debug for Manifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Manifest")
            .field("id", &self.id)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}
impl Drop for Manifest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}
impl Manifest {
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        if self.version != 1
            || self.size > MAX_FILE_BYTES
            || self.name.is_empty()
            || self.name.len() > 255
            || self
                .name
                .chars()
                .any(|c| c.is_control() || c == '/' || c == '\\')
            || matches!(self.name.as_str(), "." | "..")
            || self.id == [0; 16]
        {
            return Err(Error::Invalid("manifest"));
        }
        if self.size == 0 && (self.sha256 != hash(&[]) || self.root != empty_root()) {
            return Err(Error::Invalid("empty file digest"));
        }
        Ok(())
    }
    pub fn pieces(&self) -> usize {
        self.size.div_ceil(PIECE_BYTES as u64) as usize
    }
    pub fn piece_len(&self, index: u32) -> Result<usize> {
        if index as usize >= self.pieces() {
            return Err(Error::Invalid("piece index"));
        }
        Ok((self.size - u64::from(index) * PIECE_BYTES as u64).min(PIECE_BYTES as u64) as usize)
    }
    pub fn cipher_len(&self, index: u32) -> Result<usize> {
        Ok(self.piece_len(index)? + 28)
    }
    pub fn reservation(&self) -> u64 {
        self.size + self.pieces() as u64 * 1024 + 4096
    }
    fn aad(&self, index: u32) -> Vec<u8> {
        let mut out = b"GComs/piece/v1\0".to_vec();
        out.extend(self.id);
        out.extend(self.scope.channel);
        out.extend(self.size.to_be_bytes());
        out.extend(index.to_be_bytes());
        for member in &self.scope.participants {
            out.extend(member);
        }
        out
    }
    pub fn seal(&self, index: u32, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() != self.piece_len(index)? {
            return Err(Error::Invalid("piece length"));
        }
        let nonce: [u8; 12] = rand::random();
        let sealed = Aes256Gcm::new_from_slice(&self.key)
            .expect("key length")
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: data,
                    aad: &self.aad(index),
                },
            )
            .map_err(|_| Error::Invalid("piece encryption"))?;
        let mut out = nonce.to_vec();
        out.extend(sealed);
        Ok(out)
    }
    pub fn open(&self, index: u32, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() != self.cipher_len(index)? {
            return Err(Error::Invalid("ciphertext length"));
        }
        Aes256Gcm::new_from_slice(&self.key)
            .expect("key length")
            .decrypt(
                Nonce::from_slice(&data[..12]),
                Payload {
                    msg: &data[12..],
                    aad: &self.aad(index),
                },
            )
            .map_err(|_| Error::Invalid("piece authentication"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    Discover {
        after: Option<ShareId>,
    },
    Offers {
        manifests: Vec<Manifest>,
        next: Option<ShareId>,
    },
    Inventory {
        id: ShareId,
        start: u32,
    },
    Have {
        id: ShareId,
        start: u32,
        pieces: Vec<bool>,
    },
    Want {
        id: ShareId,
        piece: u32,
        offset: u32,
        request: [u8; 16],
    },
    Data {
        id: ShareId,
        piece: u32,
        offset: u32,
        request: [u8; 16],
        proof: Vec<Hash>,
        bytes: Vec<u8>,
    },
    Unavailable {
        id: ShareId,
        request: [u8; 16],
    },
    Complete {
        id: ShareId,
        sha256: Hash,
    },
}
impl Message {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = postcard::to_allocvec(self).map_err(|_| Error::Invalid("record encoding"))?;
        if bytes.len() > gcoms_core::APPLICATION_PAYLOAD_LIMIT - 8 - CONTENT_TYPE.len() {
            return Err(Error::Invalid("record exceeds application limit"));
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > gcoms_core::APPLICATION_PAYLOAD_LIMIT - 8 - CONTENT_TYPE.len() {
            return Err(Error::Invalid("record exceeds application limit"));
        }
        let (value, tail): (Self, _) =
            postcard::take_from_bytes(bytes).map_err(|_| Error::Invalid("record encoding"))?;
        if !tail.is_empty() {
            return Err(Error::Invalid("trailing record bytes"));
        }
        value.validate()?;
        Ok(value)
    }
    pub(super) fn validate(&self) -> Result<()> {
        match self {
            Self::Offers { manifests, .. } => {
                if manifests.len() > 8 {
                    return Err(Error::Invalid("offer page"));
                }
                for m in manifests {
                    m.validate()?;
                }
            }
            Self::Have { start, pieces, .. } => {
                if pieces.len() > INVENTORY_PAGE
                    || (*start as usize)
                        .checked_add(pieces.len())
                        .is_none_or(|end| end > MAX_PIECES)
                {
                    return Err(Error::Invalid("inventory page"));
                }
            }
            Self::Data { proof, bytes, .. }
                if proof.len() > 16 || bytes.is_empty() || bytes.len() > BLOCK_BYTES =>
            {
                return Err(Error::Invalid("data bounds"))
            }
            _ => {}
        }
        Ok(())
    }
}

pub fn hash(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}
pub fn empty_root() -> Hash {
    hash(b"GComs/empty-file/v1")
}
pub fn leaf(index: u32, bytes: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0]);
    h.update(index.to_be_bytes());
    h.update(bytes);
    h.finalize().into()
}
fn branch(left: Hash, right: Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([1]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}
pub fn tree(leaves: &[Hash]) -> Vec<Vec<Hash>> {
    if leaves.is_empty() {
        return vec![vec![empty_root()]];
    }
    let mut layer = leaves.to_vec();
    layer.resize(leaves.len().next_power_of_two(), [0; 32]);
    let mut layers = vec![layer];
    while layers.last().unwrap().len() > 1 {
        let next = layers
            .last()
            .unwrap()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| branch(p[0], p[1]))
            .collect();
        layers.push(next);
    }
    layers
}

pub fn verify(manifest: &Manifest, index: u32, data: &[u8], proof: &[Hash]) -> Result<()> {
    if data.len() != manifest.cipher_len(index)?
        || proof.len() != manifest.pieces().next_power_of_two().ilog2() as usize
    {
        return Err(Error::Invalid("Merkle proof length"));
    }
    let mut value = leaf(index, data);
    let mut pos = index;
    for sibling in proof {
        value = if pos & 1 == 0 {
            branch(value, *sibling)
        } else {
            branch(*sibling, value)
        };
        pos /= 2;
    }
    if value != manifest.root {
        return Err(Error::Invalid("Merkle proof"));
    }
    // Hash authentication does not replace the content-key/context check.
    let _ = zeroize::Zeroizing::new(manifest.open(index, data)?);
    Ok(())
}
