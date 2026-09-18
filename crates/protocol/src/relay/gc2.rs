//! GC/2 relay envelopes. Class, destination, epoch and exact ciphertext are
//! authenticated together under version-specific domains. This module does not
//! grant authority, reserve capacity, or interpret hop acceptance as delivery.
use super::{
    validate_frwd_target_with_policy, FrwdTargetPolicy, HopKey, Nonce, PushCap, QueueId,
    RelayCodecError, RelayTarget, ServiceId, SubCap, TARGET_LEN,
};
use alloc::vec::Vec;
use gcoms_core::gc2::{NaturalCell, VERSION};
use gcoms_core::{CellType, TrafficClass, HEADER_LEN, MAX_MESSAGE};
use hmac::{Hmac, Mac};
use sha2::Sha256;

const TAG_LEN: usize = 32;
const PUSH_PREFIX: usize = 67;
const SUB_PREFIX: usize = 65;
const FRWD_PREFIX: usize = 78;

fn domain(kind: CellType) -> Result<&'static [u8], RelayCodecError> {
    match kind {
        CellType::RelayPush => Ok(b"GC2/RELAY-PUSH\0"),
        CellType::RelaySub => Ok(b"GC2/RELAY-SUB\0"),
        CellType::Frwd => Ok(b"GC2/FRWD\0"),
        _ => Err(RelayCodecError::WrongCellType),
    }
}

fn mac(
    kind: CellType,
    key: &[u8; 32],
    service: &ServiceId,
    payload: &[u8],
) -> Result<Hmac<Sha256>, RelayCodecError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| RelayCodecError::Malformed)?;
    mac.update(domain(kind)?);
    mac.update(&[VERSION, kind as u8]);
    mac.update(service);
    mac.update(&(payload.len() as u16).to_be_bytes());
    mac.update(payload);
    Ok(mac)
}

fn seal(
    kind: CellType,
    key: &[u8; 32],
    service: &ServiceId,
    mut payload: Vec<u8>,
) -> Result<NaturalCell, RelayCodecError> {
    if payload.len() > gcoms_core::gc2::MAX_CELL - HEADER_LEN - TAG_LEN {
        return Err(RelayCodecError::CellTooLarge);
    }
    let tag = mac(kind, key, service, &payload)?.finalize().into_bytes();
    payload.extend_from_slice(&tag);
    NaturalCell::new(kind, 0, payload).map_err(|_| RelayCodecError::NonCanonicalCell)
}

fn body(cell: &NaturalCell, kind: CellType) -> Result<&[u8], RelayCodecError> {
    if cell.kind() != kind || cell.flags() != 0 {
        return Err(RelayCodecError::WrongCellType);
    }
    let len = cell
        .payload()
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(RelayCodecError::Malformed)?;
    Ok(&cell.payload()[..len])
}

fn authenticate<'a>(
    cell: &'a NaturalCell,
    kind: CellType,
    key: &[u8; 32],
    service: &ServiceId,
) -> Result<&'a [u8], RelayCodecError> {
    let bytes = body(cell, kind)?;
    mac(kind, key, service, bytes)?
        .verify_slice(&cell.payload()[bytes.len()..])
        .map_err(|_| RelayCodecError::InvalidMac)?;
    Ok(bytes)
}

fn class(value: u8) -> Result<TrafficClass, RelayCodecError> {
    TrafficClass::from_byte(value).ok_or(RelayCodecError::Malformed)
}

fn live(expiry: u64, now: u64) -> Result<(), RelayCodecError> {
    if expiry <= now {
        Err(RelayCodecError::Expired {
            expires_unix: expiry,
            now_unix: now,
        })
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Push {
    pub class: TrafficClass,
    pub queue_id: QueueId,
    pub epoch: u64,
    pub nonce: Nonce,
    pub expiry: u64,
    pub msg: Option<NaturalCell>,
}

impl Push {
    pub fn encode(
        &self,
        cap: &PushCap,
        service: &ServiceId,
    ) -> Result<NaturalCell, RelayCodecError> {
        let msg = match &self.msg {
            Some(msg) if msg.kind() == CellType::Msg => msg.encode(),
            Some(_) => return Err(RelayCodecError::InnerNotMsg),
            None => Vec::new(),
        };
        let mut payload = Vec::with_capacity(PUSH_PREFIX + msg.len() + TAG_LEN);
        payload.push(self.class as u8);
        payload.extend_from_slice(&self.queue_id);
        payload.extend_from_slice(&self.epoch.to_be_bytes());
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(&self.expiry.to_be_bytes());
        payload.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        payload.extend_from_slice(&msg);
        seal(CellType::RelayPush, cap, service, payload)
    }

    pub fn decode(
        cell: &NaturalCell,
        cap: &PushCap,
        service: &ServiceId,
        now: u64,
    ) -> Result<Self, RelayCodecError> {
        let parsed = Self::parse(authenticate(cell, CellType::RelayPush, cap, service)?)?;
        live(parsed.expiry, now)?;
        Ok(parsed)
    }

    fn parse(bytes: &[u8]) -> Result<Self, RelayCodecError> {
        if bytes.len() < PUSH_PREFIX {
            return Err(RelayCodecError::Malformed);
        }
        let len = u16::from_be_bytes(bytes[65..67].try_into().unwrap()) as usize;
        if len > MAX_MESSAGE + HEADER_LEN || len != bytes.len() - PUSH_PREFIX {
            return Err(RelayCodecError::Malformed);
        }
        let msg = if len == 0 {
            None
        } else {
            let msg = NaturalCell::decode(&bytes[PUSH_PREFIX..])
                .map_err(|_| RelayCodecError::NonCanonicalCell)?;
            if msg.kind() != CellType::Msg {
                return Err(RelayCodecError::InnerNotMsg);
            }
            Some(msg)
        };
        Ok(Self {
            class: class(bytes[0])?,
            queue_id: bytes[1..33].try_into().unwrap(),
            epoch: u64::from_be_bytes(bytes[33..41].try_into().unwrap()),
            nonce: bytes[41..57].try_into().unwrap(),
            expiry: u64::from_be_bytes(bytes[57..65].try_into().unwrap()),
            msg,
        })
    }
}

/// Canonical shape only. Possession of this value never authenticates its
/// destination capability; only the destination may call `authenticate`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnverifiedPush {
    cell: NaturalCell,
    class: TrafficClass,
    queue_id: QueueId,
    expiry: u64,
}

impl UnverifiedPush {
    pub fn parse(cell: NaturalCell) -> Result<Self, RelayCodecError> {
        let parsed = Push::parse(body(&cell, CellType::RelayPush)?)?;
        Ok(Self {
            cell,
            class: parsed.class,
            queue_id: parsed.queue_id,
            expiry: parsed.expiry,
        })
    }
    pub fn class(&self) -> TrafficClass {
        self.class
    }
    pub fn queue_id(&self) -> QueueId {
        self.queue_id
    }
    pub fn expiry(&self) -> u64 {
        self.expiry
    }
    pub fn as_cell(&self) -> &NaturalCell {
        &self.cell
    }
    pub fn into_cell(self) -> NaturalCell {
        self.cell
    }
    pub fn authenticate(
        self,
        cap: &PushCap,
        service: &ServiceId,
        now: u64,
    ) -> Result<Push, RelayCodecError> {
        Push::decode(&self.cell, cap, service, now)
    }
}

/// One authenticated class per subscription; it cannot drain the other class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subscription {
    pub class: TrafficClass,
    pub queue_id: QueueId,
    pub epoch: u64,
    pub expiry: u64,
    pub nonce: Nonce,
}

impl Subscription {
    pub fn encode(
        &self,
        cap: &SubCap,
        service: &ServiceId,
    ) -> Result<NaturalCell, RelayCodecError> {
        let mut payload = Vec::with_capacity(SUB_PREFIX + TAG_LEN);
        payload.push(self.class as u8);
        payload.extend_from_slice(&self.queue_id);
        payload.extend_from_slice(&self.epoch.to_be_bytes());
        payload.extend_from_slice(&self.expiry.to_be_bytes());
        payload.extend_from_slice(&self.nonce);
        seal(CellType::RelaySub, cap, service, payload)
    }

    pub fn decode(
        cell: &NaturalCell,
        cap: &SubCap,
        service: &ServiceId,
        now: u64,
    ) -> Result<Self, RelayCodecError> {
        let bytes = authenticate(cell, CellType::RelaySub, cap, service)?;
        if bytes.len() != SUB_PREFIX {
            return Err(RelayCodecError::Malformed);
        }
        let value = Self {
            class: class(bytes[0])?,
            queue_id: bytes[1..33].try_into().unwrap(),
            epoch: u64::from_be_bytes(bytes[33..41].try_into().unwrap()),
            expiry: u64::from_be_bytes(bytes[41..49].try_into().unwrap()),
            nonce: bytes[49..65].try_into().unwrap(),
        };
        live(value.expiry, now)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forward {
    pub class: TrafficClass,
    pub target: RelayTarget,
    pub expiry: u64,
    pub nonce: Nonce,
    pub push: Option<UnverifiedPush>,
}

impl Forward {
    pub fn encode(
        &self,
        key: &HopKey,
        service: &ServiceId,
        policy: &FrwdTargetPolicy,
    ) -> Result<NaturalCell, RelayCodecError> {
        validate_frwd_target_with_policy(&self.target, policy)?;
        let push = match &self.push {
            Some(push) if push.class() == self.class => push.as_cell().encode(),
            Some(_) => return Err(RelayCodecError::NonCanonicalCell),
            None => Vec::new(),
        };
        let mut payload = Vec::with_capacity(FRWD_PREFIX + push.len() + TAG_LEN);
        payload.push(self.class as u8);
        payload.extend_from_slice(&self.target.encode());
        payload.extend_from_slice(&self.expiry.to_be_bytes());
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(&(push.len() as u16).to_be_bytes());
        payload.extend_from_slice(&push);
        seal(CellType::Frwd, key, service, payload)
    }

    pub fn decode(
        cell: &NaturalCell,
        key: &HopKey,
        service: &ServiceId,
        now: u64,
        policy: &FrwdTargetPolicy,
    ) -> Result<Self, RelayCodecError> {
        let bytes = authenticate(cell, CellType::Frwd, key, service)?;
        if bytes.len() < FRWD_PREFIX {
            return Err(RelayCodecError::Malformed);
        }
        let traffic = class(bytes[0])?;
        let target = RelayTarget::decode(&bytes[1..1 + TARGET_LEN])?;
        validate_frwd_target_with_policy(&target, policy)?;
        let expiry = u64::from_be_bytes(bytes[52..60].try_into().unwrap());
        live(expiry, now)?;
        let len = u16::from_be_bytes(bytes[76..78].try_into().unwrap()) as usize;
        if len != bytes.len() - FRWD_PREFIX {
            return Err(RelayCodecError::Malformed);
        }
        let push = if len == 0 {
            None
        } else {
            let push = UnverifiedPush::parse(
                NaturalCell::decode(&bytes[FRWD_PREFIX..])
                    .map_err(|_| RelayCodecError::NonCanonicalCell)?,
            )?;
            if push.class() != traffic {
                return Err(RelayCodecError::NonCanonicalCell);
            }
            live(push.expiry(), now)?;
            Some(push)
        };
        Ok(Self {
            class: traffic,
            target,
            expiry,
            nonce: bytes[60..76].try_into().unwrap(),
            push,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn push(traffic: TrafficClass) -> Push {
        Push {
            class: traffic,
            queue_id: [1; 32],
            epoch: 7,
            nonce: [2; 16],
            expiry: 200,
            msg: Some(NaturalCell::new(CellType::Msg, 0, vec![42; MAX_MESSAGE]).unwrap()),
        }
    }

    #[test]
    fn maximum_message_and_forward_chain_roundtrip_without_inner_padding() {
        for class in [TrafficClass::Interactive, TrafficClass::Bulk] {
            let original = push(class);
            let encoded = original.encode(&[3; 32], &[4; 32]).unwrap();
            assert_eq!(
                encoded.encoded_len(),
                MAX_MESSAGE + HEADER_LEN * 2 + PUSH_PREFIX + TAG_LEN
            );
            let forward = Forward {
                class,
                target: RelayTarget {
                    address: "192.0.2.1:443".parse().unwrap(),
                    relay_service_id: [4; 32],
                },
                expiry: 150,
                nonce: [5; 16],
                push: Some(UnverifiedPush::parse(encoded).unwrap()),
            };
            let policy = FrwdTargetPolicy::new(true);
            let wire = forward.encode(&[6; 32], &[7; 32], &policy).unwrap();
            assert!(wire.encoded_len() <= gcoms_core::gc2::MAX_CELL);
            let decoded = Forward::decode(&wire, &[6; 32], &[7; 32], 100, &policy).unwrap();
            assert_eq!(decoded, forward);
            assert_eq!(
                decoded
                    .push
                    .unwrap()
                    .authenticate(&[3; 32], &[4; 32], 100)
                    .unwrap(),
                original
            );
        }
    }

    #[test]
    fn authenticated_class_destination_and_ciphertext_cannot_be_rewritten() {
        let encoded = push(TrafficClass::Bulk).encode(&[3; 32], &[4; 32]).unwrap();
        for offset in [0, 1, 33, 41, 57, 65, PUSH_PREFIX + HEADER_LEN] {
            let mut bytes = encoded.payload().to_vec();
            bytes[offset] ^= 1;
            let changed = NaturalCell::new(CellType::RelayPush, 0, bytes).unwrap();
            assert_eq!(
                Push::decode(&changed, &[3; 32], &[4; 32], 100),
                Err(RelayCodecError::InvalidMac)
            );
        }
        assert!(Push::decode(&encoded, &[3; 32], &[8; 32], 100).is_err());
        assert!(Push::decode(&encoded, &[8; 32], &[4; 32], 100).is_err());
        assert!(Push::decode(&encoded, &[3; 32], &[4; 32], 200).is_err());
        let relabeled = NaturalCell::new(CellType::RelaySub, 0, encoded.into_payload()).unwrap();
        assert_eq!(
            Subscription::decode(&relabeled, &[3; 32], &[4; 32], 100),
            Err(RelayCodecError::InvalidMac)
        );
    }

    #[test]
    fn subscriptions_bind_exact_class_and_expiry() {
        for class in [TrafficClass::Interactive, TrafficClass::Bulk] {
            let sub = Subscription {
                class,
                queue_id: [1; 32],
                epoch: 7,
                expiry: 200,
                nonce: [2; 16],
            };
            let cell = sub.encode(&[3; 32], &[4; 32]).unwrap();
            assert_eq!(
                Subscription::decode(&cell, &[3; 32], &[4; 32], 100).unwrap(),
                sub
            );
            assert!(Subscription::decode(&cell, &[3; 32], &[4; 32], 200).is_err());
            let mut changed = cell.into_payload();
            changed[0] ^= 1;
            let changed = NaturalCell::new(CellType::RelaySub, 0, changed).unwrap();
            assert_eq!(
                Subscription::decode(&changed, &[3; 32], &[4; 32], 100),
                Err(RelayCodecError::InvalidMac)
            );
        }
    }

    #[test]
    fn class_mismatch_expired_nested_push_and_target_policy_fail_closed() {
        let push =
            UnverifiedPush::parse(push(TrafficClass::Bulk).encode(&[3; 32], &[4; 32]).unwrap())
                .unwrap();
        let mut forward = Forward {
            class: TrafficClass::Interactive,
            target: RelayTarget {
                address: "127.0.0.1:443".parse().unwrap(),
                relay_service_id: [4; 32],
            },
            expiry: 300,
            nonce: [5; 16],
            push: Some(push),
        };
        let fixture = FrwdTargetPolicy::new(true);
        assert!(forward.encode(&[6; 32], &[7; 32], &fixture).is_err());
        forward.class = TrafficClass::Bulk;
        let encoded = forward.encode(&[6; 32], &[7; 32], &fixture).unwrap();
        assert!(Forward::decode(&encoded, &[6; 32], &[7; 32], 200, &fixture).is_err());
        assert!(Forward::decode(
            &encoded,
            &[6; 32],
            &[7; 32],
            100,
            &FrwdTargetPolicy::new(false)
        )
        .is_err());
        // Even an authorized intermediary cannot supply contradictory classes.
        let mut changed = body(&encoded, CellType::Frwd).unwrap().to_vec();
        changed[0] = TrafficClass::Interactive as u8;
        let changed = seal(CellType::Frwd, &[6; 32], &[7; 32], changed).unwrap();
        assert_eq!(
            Forward::decode(&changed, &[6; 32], &[7; 32], 100, &fixture),
            Err(RelayCodecError::NonCanonicalCell)
        );
    }

    #[test]
    fn version_relabeling_cannot_reuse_a_gc1_capability_tag() {
        let old = super::super::RelayPush {
            queue_id: [1; 32],
            epoch: 7,
            push_nonce: [2; 16],
            push_expiry: 200,
            msg: None,
        }
        .encode_into_cell(&[3; 32], &[4; 32])
        .unwrap();
        // GC/1's payload version byte happens to equal GC/2's bulk class.
        // Shape alone must never be enough to cross the version boundary.
        let relabeled = NaturalCell::new(CellType::RelayPush, 0, old.payload).unwrap();
        assert!(UnverifiedPush::parse(relabeled.clone()).is_ok());
        assert_eq!(
            Push::decode(&relabeled, &[3; 32], &[4; 32], 100),
            Err(RelayCodecError::InvalidMac)
        );
        let new = Push {
            msg: None,
            ..push(TrafficClass::Bulk)
        }
        .encode(&[3; 32], &[4; 32])
        .unwrap();
        let relabeled = gcoms_core::Cell::new(CellType::RelayPush, 0, 0, new.into_payload());
        assert_eq!(
            super::super::RelayPush::decode_from_cell(&relabeled, &[3; 32], &[4; 32], 100),
            Err(RelayCodecError::InvalidMac)
        );
    }
}
