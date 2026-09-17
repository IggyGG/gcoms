use base64ct::Encoding;
use core::error::Error;
use core::fmt;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const VERSION: u8 = 1;
pub const OP_CREATE: u8 = 0x01;
pub const OP_RENEW: u8 = 0x02;
pub const OP_ROTATE: u8 = 0x03;
pub const OP_REVOKE: u8 = 0x04;
pub const OP_SUBSCRIBE: u8 = 0x05;
pub const OP_GRANT_REQUEST: u8 = 0x06;

pub const ADMISSION_GRANT_LEN: usize = 180;
pub const LEASE_CREATE_LEN: usize = 386;
pub const LEASE_RENEW_LEN: usize = 98;
pub const LEASE_ROTATE_LEN: usize = 202;
pub const LEASE_REVOKE_LEN: usize = 98;
pub const GRANT_REQUEST_LEN: usize = 148;
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;

const TAG_LEN: usize = 32;
const GRANT_DOMAIN: &[u8] = b"GC1/ADMISSION-GRANT\0";
const CREATE_DOMAIN: &[u8] = b"GC1/LEASE-CREATE\0";
const RENEW_DOMAIN: &[u8] = b"GC1/LEASE-RENEW\0";
const ROTATE_DOMAIN: &[u8] = b"GC1/LEASE-ROTATE\0";
const REVOKE_DOMAIN: &[u8] = b"GC1/LEASE-REVOKE\0";
const GRANT_REQUEST_DOMAIN: &[u8] = b"GC1/CHANNEL-GRANT-REQUEST\0";
const EMPTY_FIELD: [u8; 2] = [0, 0];

pub type RelayServiceId = [u8; 32];
pub type QueueId = [u8; 32];
pub type Capability = [u8; 32];
pub type AdmissionKey = [u8; 32];
pub type Nonce = [u8; 16];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidationPolicy {
    pub now_unix: u64,
    pub clock_skew_secs: u64,
    pub max_expiry_unix: u64,
}

impl ValidationPolicy {
    pub fn new(
        now_unix: u64,
        clock_skew_secs: u64,
        max_expiry_unix: u64,
    ) -> Result<Self, LeaseCodecError> {
        if clock_skew_secs > MAX_CLOCK_SKEW_SECS {
            return Err(LeaseCodecError::ClockSkewTooLarge(clock_skew_secs));
        }
        Ok(Self {
            now_unix,
            clock_skew_secs,
            max_expiry_unix,
        })
    }

    fn validate_expiry(&self, expiry_unix: u64) -> Result<(), LeaseCodecError> {
        if expiry_unix.saturating_add(self.clock_skew_secs) <= self.now_unix {
            return Err(LeaseCodecError::Expired {
                expiry_unix,
                now_unix: self.now_unix,
            });
        }
        if expiry_unix > self.max_expiry_unix {
            return Err(LeaseCodecError::ExpiryExceedsPolicy {
                expiry_unix,
                max_expiry_unix: self.max_expiry_unix,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseLimits {
    pub max_queue_cells: u16,
    pub max_queue_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub push: Capability,
    pub sub: Capability,
    pub admin: Capability,
}

impl Capabilities {
    fn validate(&self, queue_id: &QueueId) -> Result<(), LeaseCodecError> {
        require_random("queue_id", queue_id)?;
        require_random("push_cap", &self.push)?;
        require_random("sub_cap", &self.sub)?;
        require_random("admin_cap", &self.admin)?;
        let values = [queue_id, &self.push, &self.sub, &self.admin];
        for left in 0..values.len() {
            for right in left + 1..values.len() {
                if values[left] == values[right] {
                    return Err(LeaseCodecError::CapabilitiesNotIndependent);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeaseCodecError {
    WrongLength {
        expected: usize,
        actual: usize,
    },
    InvalidVersion(u8),
    InvalidOperation {
        expected: u8,
        actual: u8,
    },
    InvalidGrantLength(u16),
    InvalidMac,
    RelayServiceMismatch,
    QueueBindingMismatch,
    EpochBindingMismatch,
    ClockSkewTooLarge(u64),
    NotYetValid {
        not_before: u64,
        now_unix: u64,
    },
    Expired {
        expiry_unix: u64,
        now_unix: u64,
    },
    ExpiryExceedsPolicy {
        expiry_unix: u64,
        max_expiry_unix: u64,
    },
    InvalidGrantWindow,
    ZeroRandomField(&'static str),
    ZeroEpoch,
    CapabilitiesNotIndependent,
    CapabilityWasNotRotated,
    GrantLimitExceeded,
    RelayLimitExceeded,
    RenewalDoesNotExtend,
    EpochOverflow,
    InvalidNewEpoch {
        expected: u64,
        actual: u64,
    },
    AuthorityBindingMismatch,
    HmacInitialization,
}

impl fmt::Display for LeaseCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => {
                write!(f, "wrong wire length: expected {expected}, got {actual}")
            }
            Self::InvalidVersion(version) => write!(f, "invalid version {version}"),
            Self::InvalidOperation { expected, actual } => {
                write!(
                    f,
                    "invalid operation: expected {expected:#04x}, got {actual:#04x}"
                )
            }
            Self::InvalidGrantLength(length) => write!(f, "invalid grant length {length}"),
            Self::InvalidMac => write!(f, "invalid HMAC"),
            Self::RelayServiceMismatch => write!(f, "relay service ID mismatch"),
            Self::QueueBindingMismatch => write!(f, "grant queue binding mismatch"),
            Self::EpochBindingMismatch => write!(f, "grant epoch binding mismatch"),
            Self::ClockSkewTooLarge(skew) => write!(f, "clock skew {skew} exceeds 300 seconds"),
            Self::NotYetValid {
                not_before,
                now_unix,
            } => {
                write!(f, "grant is not valid before {not_before} (now {now_unix})")
            }
            Self::Expired {
                expiry_unix,
                now_unix,
            } => {
                write!(f, "value expired at {expiry_unix} (now {now_unix})")
            }
            Self::ExpiryExceedsPolicy {
                expiry_unix,
                max_expiry_unix,
            } => write!(
                f,
                "expiry {expiry_unix} exceeds policy maximum {max_expiry_unix}"
            ),
            Self::InvalidGrantWindow => write!(f, "invalid admission grant time window"),
            Self::ZeroRandomField(field) => write!(f, "{field} must be independently random"),
            Self::ZeroEpoch => write!(f, "epoch must be nonzero"),
            Self::CapabilitiesNotIndependent => {
                write!(f, "queue ID and capabilities must be independently random")
            }
            Self::CapabilityWasNotRotated => write!(f, "a new capability equals an old capability"),
            Self::GrantLimitExceeded => write!(f, "requested queue limits exceed the grant"),
            Self::RelayLimitExceeded => write!(f, "requested queue limits exceed relay policy"),
            Self::RenewalDoesNotExtend => write!(f, "renewal does not extend the lease"),
            Self::EpochOverflow => write!(f, "old epoch cannot be incremented"),
            Self::InvalidNewEpoch { expected, actual } => {
                write!(f, "invalid new epoch: expected {expected}, got {actual}")
            }
            Self::AuthorityBindingMismatch => write!(f, "grant authority binding mismatch"),
            Self::HmacInitialization => write!(f, "failed to initialize HMAC"),
        }
    }
}

impl Error for LeaseCodecError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DynamicGrantRequest {
    pub authority_queue_id: QueueId,
    pub authority_epoch: u64,
    pub queue_id: QueueId,
    pub epoch: u64,
    pub limits: LeaseLimits,
    pub nonce: Nonce,
    pub expiry: u64,
}

impl DynamicGrantRequest {
    pub fn encode(
        &self,
        admin_cap: &Capability,
        relay_service_id: &RelayServiceId,
    ) -> Result<[u8; GRANT_REQUEST_LEN], LeaseCodecError> {
        self.validate()?;
        let mut wire = [0u8; GRANT_REQUEST_LEN];
        let mut writer = Writer::new(&mut wire);
        writer.byte(VERSION);
        writer.byte(OP_GRANT_REQUEST);
        writer.bytes(&self.authority_queue_id);
        writer.u64(self.authority_epoch);
        writer.bytes(&self.queue_id);
        writer.u64(self.epoch);
        writer.u16(self.limits.max_queue_cells);
        writer.u64(self.limits.max_queue_bytes);
        writer.bytes(&self.nonce);
        writer.u64(self.expiry);
        let authenticated_len = writer.position();
        let mut mac = new_mac(admin_cap)?;
        mac.update(GRANT_REQUEST_DOMAIN);
        mac.update(relay_service_id);
        mac.update(&wire[..authenticated_len]);
        wire[authenticated_len..].copy_from_slice(&mac.finalize().into_bytes());
        Ok(wire)
    }

    pub fn decode_and_verify(
        wire: &[u8],
        admin_cap: &Capability,
        relay_service_id: &RelayServiceId,
        authority_queue_id: &QueueId,
        authority_epoch: u64,
        policy: ValidationPolicy,
    ) -> Result<Self, LeaseCodecError> {
        require_len(wire, GRANT_REQUEST_LEN)?;
        require_header(wire[0], wire[1], OP_GRANT_REQUEST)?;
        let authenticated_len = GRANT_REQUEST_LEN - TAG_LEN;
        let mut mac = new_mac(admin_cap)?;
        mac.update(GRANT_REQUEST_DOMAIN);
        mac.update(relay_service_id);
        mac.update(&wire[..authenticated_len]);
        mac.verify_slice(&wire[authenticated_len..])
            .map_err(|_| LeaseCodecError::InvalidMac)?;
        let mut reader = Reader::new(&wire[..authenticated_len]);
        reader.byte()?;
        reader.byte()?;
        let value = Self {
            authority_queue_id: reader.array()?,
            authority_epoch: reader.u64()?,
            queue_id: reader.array()?,
            epoch: reader.u64()?,
            limits: LeaseLimits {
                max_queue_cells: reader.u16()?,
                max_queue_bytes: reader.u64()?,
            },
            nonce: reader.array()?,
            expiry: reader.u64()?,
        };
        if value.authority_queue_id != *authority_queue_id
            || value.authority_epoch != authority_epoch
        {
            return Err(LeaseCodecError::AuthorityBindingMismatch);
        }
        value.validate()?;
        policy.validate_expiry(value.expiry)?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), LeaseCodecError> {
        require_random("authority_queue_id", &self.authority_queue_id)?;
        require_random("queue_id", &self.queue_id)?;
        require_random("nonce", &self.nonce)?;
        if self.authority_epoch == 0 || self.epoch == 0 {
            return Err(LeaseCodecError::ZeroEpoch);
        }
        if self.authority_queue_id == self.queue_id {
            return Err(LeaseCodecError::CapabilitiesNotIndependent);
        }
        if self.limits.max_queue_cells == 0 || self.limits.max_queue_bytes == 0 {
            return Err(LeaseCodecError::GrantLimitExceeded);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionGrant {
    pub relay_service_id: RelayServiceId,
    pub grant_id: [u8; 16],
    pub grant_cap: Capability,
    pub queue_id: QueueId,
    pub epoch: u64,
    pub not_before: u64,
    pub expiry: u64,
    pub max_queue_cells: u16,
    pub max_queue_bytes: u64,
}

impl AdmissionGrant {
    pub fn encode(
        &self,
        admit_key: &AdmissionKey,
    ) -> Result<[u8; ADMISSION_GRANT_LEN], LeaseCodecError> {
        let mut wire = [0u8; ADMISSION_GRANT_LEN];
        let mut writer = Writer::new(&mut wire);
        writer.byte(VERSION);
        writer.bytes(&self.relay_service_id);
        writer.bytes(&self.grant_id);
        writer.bytes(&self.grant_cap);
        writer.byte(OP_CREATE);
        writer.bytes(&self.queue_id);
        writer.u64(self.epoch);
        writer.u64(self.not_before);
        writer.u64(self.expiry);
        writer.u16(self.max_queue_cells);
        writer.u64(self.max_queue_bytes);
        let authenticated_len = writer.position();

        let mut mac = new_mac(admit_key)?;
        mac.update(GRANT_DOMAIN);
        mac.update(&wire[..authenticated_len]);
        mac.update(&EMPTY_FIELD);
        wire[authenticated_len..].copy_from_slice(&mac.finalize().into_bytes());
        Ok(wire)
    }

    pub fn decode_and_verify(
        wire: &[u8],
        admit_key: &AdmissionKey,
        relay_service_id: &RelayServiceId,
        policy: ValidationPolicy,
    ) -> Result<Self, LeaseCodecError> {
        require_len(wire, ADMISSION_GRANT_LEN)?;
        require_header(wire[0], wire[81], OP_CREATE)?;
        if wire[1..33] != relay_service_id[..] {
            return Err(LeaseCodecError::RelayServiceMismatch);
        }
        let authenticated_len = ADMISSION_GRANT_LEN - TAG_LEN;
        let mut mac = new_mac(admit_key)?;
        mac.update(GRANT_DOMAIN);
        mac.update(&wire[..authenticated_len]);
        mac.update(&EMPTY_FIELD);
        mac.verify_slice(&wire[authenticated_len..])
            .map_err(|_| LeaseCodecError::InvalidMac)?;

        let value = Self::decode_body(wire)?;
        value.validate(policy)?;
        Ok(value)
    }

    fn decode_body(wire: &[u8]) -> Result<Self, LeaseCodecError> {
        require_len(wire, ADMISSION_GRANT_LEN)?;
        require_header(wire[0], wire[81], OP_CREATE)?;
        let authenticated_len = ADMISSION_GRANT_LEN - TAG_LEN;
        let mut reader = Reader::new(&wire[..authenticated_len]);
        reader.byte()?;
        Ok(Self {
            relay_service_id: reader.array()?,
            grant_id: reader.array()?,
            grant_cap: reader.array()?,
            queue_id: {
                reader.byte()?;
                reader.array()?
            },
            epoch: reader.u64()?,
            not_before: reader.u64()?,
            expiry: reader.u64()?,
            max_queue_cells: reader.u16()?,
            max_queue_bytes: reader.u64()?,
        })
    }

    pub fn validate(&self, policy: ValidationPolicy) -> Result<(), LeaseCodecError> {
        validate_policy(policy)?;
        require_random("grant_id", &self.grant_id)?;
        require_random("grant_cap", &self.grant_cap)?;
        require_random("queue_id", &self.queue_id)?;
        if self.epoch == 0 {
            return Err(LeaseCodecError::ZeroEpoch);
        }
        if self.not_before >= self.expiry {
            return Err(LeaseCodecError::InvalidGrantWindow);
        }
        if self.not_before > policy.now_unix.saturating_add(policy.clock_skew_secs) {
            return Err(LeaseCodecError::NotYetValid {
                not_before: self.not_before,
                now_unix: policy.now_unix,
            });
        }
        policy.validate_expiry(self.expiry)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseCreate {
    pub queue_id: QueueId,
    pub epoch: u64,
    pub lease_expiry: u64,
    pub queue_cells: u16,
    pub queue_bytes: u64,
    pub capabilities: Capabilities,
    pub nonce: Nonce,
    pub grant: [u8; ADMISSION_GRANT_LEN],
}

impl LeaseCreate {
    pub fn encode(
        &self,
        relay_service_id: &RelayServiceId,
    ) -> Result<[u8; LEASE_CREATE_LEN], LeaseCodecError> {
        let grant_cap: Capability = self.grant[49..81]
            .try_into()
            .map_err(|_| LeaseCodecError::InvalidGrantLength(ADMISSION_GRANT_LEN as u16))?;
        let mut wire = [0u8; LEASE_CREATE_LEN];
        let mut writer = Writer::new(&mut wire);
        writer.byte(VERSION);
        writer.byte(OP_CREATE);
        writer.bytes(&self.queue_id);
        writer.u64(self.epoch);
        writer.u64(self.lease_expiry);
        writer.u16(self.queue_cells);
        writer.u64(self.queue_bytes);
        writer.bytes(&self.capabilities.push);
        writer.bytes(&self.capabilities.sub);
        writer.bytes(&self.capabilities.admin);
        writer.bytes(&self.nonce);
        writer.u16(ADMISSION_GRANT_LEN as u16);
        writer.bytes(&self.grant);
        let tag_offset = writer.position();
        let mac = create_mac(self, relay_service_id, &grant_cap)?;
        wire[tag_offset..].copy_from_slice(&mac.finalize().into_bytes());
        Ok(wire)
    }

    pub fn decode_and_verify(
        wire: &[u8],
        admit_key: &AdmissionKey,
        relay_service_id: &RelayServiceId,
        grant_policy: ValidationPolicy,
        lease_policy: ValidationPolicy,
        relay_limits: LeaseLimits,
    ) -> Result<Self, LeaseCodecError> {
        require_len(wire, LEASE_CREATE_LEN)?;
        require_header(wire[0], wire[1], OP_CREATE)?;
        let grant_len = u16::from_be_bytes([wire[172], wire[173]]);
        if grant_len != ADMISSION_GRANT_LEN as u16 {
            return Err(LeaseCodecError::InvalidGrantLength(grant_len));
        }
        let value = Self::decode_body(wire)?;
        let grant = AdmissionGrant::decode_and_verify(
            &value.grant,
            admit_key,
            relay_service_id,
            grant_policy,
        )?;
        let mac = create_mac(&value, relay_service_id, &grant.grant_cap)?;
        mac.verify_slice(&wire[LEASE_CREATE_LEN - TAG_LEN..])
            .map_err(|_| LeaseCodecError::InvalidMac)?;
        value.validate(&grant, lease_policy, relay_limits)?;
        Ok(value)
    }

    fn decode_body(wire: &[u8]) -> Result<Self, LeaseCodecError> {
        require_len(wire, LEASE_CREATE_LEN)?;
        require_header(wire[0], wire[1], OP_CREATE)?;
        let grant_len = u16::from_be_bytes([wire[172], wire[173]]);
        if grant_len != ADMISSION_GRANT_LEN as u16 {
            return Err(LeaseCodecError::InvalidGrantLength(grant_len));
        }
        let mut reader = Reader::new(&wire[..LEASE_CREATE_LEN - TAG_LEN]);
        reader.byte()?;
        reader.byte()?;
        Ok(Self {
            queue_id: reader.array()?,
            epoch: reader.u64()?,
            lease_expiry: reader.u64()?,
            queue_cells: reader.u16()?,
            queue_bytes: reader.u64()?,
            capabilities: Capabilities {
                push: reader.array()?,
                sub: reader.array()?,
                admin: reader.array()?,
            },
            nonce: reader.array()?,
            grant: {
                reader.u16()?;
                reader.array()?
            },
        })
    }

    pub fn validate(
        &self,
        grant: &AdmissionGrant,
        policy: ValidationPolicy,
        relay_limits: LeaseLimits,
    ) -> Result<(), LeaseCodecError> {
        validate_policy(policy)?;
        if self.epoch == 0 {
            return Err(LeaseCodecError::ZeroEpoch);
        }
        if self.queue_id != grant.queue_id {
            return Err(LeaseCodecError::QueueBindingMismatch);
        }
        if self.epoch != grant.epoch {
            return Err(LeaseCodecError::EpochBindingMismatch);
        }
        self.capabilities.validate(&self.queue_id)?;
        require_random("nonce", &self.nonce)?;
        policy.validate_expiry(self.lease_expiry)?;
        if self.queue_cells > grant.max_queue_cells || self.queue_bytes > grant.max_queue_bytes {
            return Err(LeaseCodecError::GrantLimitExceeded);
        }
        if self.queue_cells > relay_limits.max_queue_cells
            || self.queue_bytes > relay_limits.max_queue_bytes
        {
            return Err(LeaseCodecError::RelayLimitExceeded);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseRenew {
    pub queue_id: QueueId,
    pub epoch: u64,
    pub lease_expiry: u64,
    pub nonce: Nonce,
}

impl LeaseRenew {
    pub fn encode(
        &self,
        admin_cap: &Capability,
        relay_service_id: &RelayServiceId,
    ) -> Result<[u8; LEASE_RENEW_LEN], LeaseCodecError> {
        encode_short(
            OP_RENEW,
            RENEW_DOMAIN,
            &self.queue_id,
            self.epoch,
            self.lease_expiry,
            &self.nonce,
            admin_cap,
            relay_service_id,
        )
    }

    pub fn decode_and_verify(
        wire: &[u8],
        admin_cap: &Capability,
        relay_service_id: &RelayServiceId,
        current_expiry: u64,
        policy: ValidationPolicy,
    ) -> Result<Self, LeaseCodecError> {
        let (queue_id, epoch, lease_expiry, nonce) =
            decode_short(wire, OP_RENEW, RENEW_DOMAIN, admin_cap, relay_service_id)?;
        let value = Self {
            queue_id,
            epoch,
            lease_expiry,
            nonce,
        };
        validate_policy(policy)?;
        require_random("nonce", &value.nonce)?;
        policy.validate_expiry(value.lease_expiry)?;
        if value.lease_expiry <= current_expiry {
            return Err(LeaseCodecError::RenewalDoesNotExtend);
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseRotate {
    pub queue_id: QueueId,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub lease_expiry: u64,
    pub new_capabilities: Capabilities,
    pub nonce: Nonce,
}

impl LeaseRotate {
    pub fn encode(
        &self,
        admin_cap: &Capability,
        relay_service_id: &RelayServiceId,
    ) -> Result<[u8; LEASE_ROTATE_LEN], LeaseCodecError> {
        let mut wire = [0u8; LEASE_ROTATE_LEN];
        let mut writer = Writer::new(&mut wire);
        writer.byte(VERSION);
        writer.byte(OP_ROTATE);
        writer.bytes(&self.queue_id);
        writer.u64(self.old_epoch);
        writer.u64(self.new_epoch);
        writer.u64(self.lease_expiry);
        writer.bytes(&self.new_capabilities.push);
        writer.bytes(&self.new_capabilities.sub);
        writer.bytes(&self.new_capabilities.admin);
        writer.bytes(&self.nonce);
        let tag_offset = writer.position();
        let mac = rotate_mac(self, relay_service_id, admin_cap)?;
        wire[tag_offset..].copy_from_slice(&mac.finalize().into_bytes());
        Ok(wire)
    }

    pub fn decode_and_verify(
        wire: &[u8],
        current_capabilities: &Capabilities,
        relay_service_id: &RelayServiceId,
        policy: ValidationPolicy,
    ) -> Result<Self, LeaseCodecError> {
        require_len(wire, LEASE_ROTATE_LEN)?;
        require_header(wire[0], wire[1], OP_ROTATE)?;
        let mut reader = Reader::new(&wire[..LEASE_ROTATE_LEN - TAG_LEN]);
        reader.byte()?;
        reader.byte()?;
        let value = Self {
            queue_id: reader.array()?,
            old_epoch: reader.u64()?,
            new_epoch: reader.u64()?,
            lease_expiry: reader.u64()?,
            new_capabilities: Capabilities {
                push: reader.array()?,
                sub: reader.array()?,
                admin: reader.array()?,
            },
            nonce: reader.array()?,
        };
        let mac = rotate_mac(&value, relay_service_id, &current_capabilities.admin)?;
        mac.verify_slice(&wire[LEASE_ROTATE_LEN - TAG_LEN..])
            .map_err(|_| LeaseCodecError::InvalidMac)?;
        value.validate(current_capabilities, policy)?;
        Ok(value)
    }

    pub fn validate(
        &self,
        current_capabilities: &Capabilities,
        policy: ValidationPolicy,
    ) -> Result<(), LeaseCodecError> {
        validate_policy(policy)?;
        let expected = self
            .old_epoch
            .checked_add(1)
            .ok_or(LeaseCodecError::EpochOverflow)?;
        if self.new_epoch != expected {
            return Err(LeaseCodecError::InvalidNewEpoch {
                expected,
                actual: self.new_epoch,
            });
        }
        self.new_capabilities.validate(&self.queue_id)?;
        let old = [
            &current_capabilities.push,
            &current_capabilities.sub,
            &current_capabilities.admin,
        ];
        let new = [
            &self.new_capabilities.push,
            &self.new_capabilities.sub,
            &self.new_capabilities.admin,
        ];
        if new
            .iter()
            .any(|new_cap| old.iter().any(|old_cap| new_cap == old_cap))
        {
            return Err(LeaseCodecError::CapabilityWasNotRotated);
        }
        require_random("nonce", &self.nonce)?;
        policy.validate_expiry(self.lease_expiry)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseRevoke {
    pub queue_id: QueueId,
    pub epoch: u64,
    pub operation_expiry: u64,
    pub nonce: Nonce,
}

impl LeaseRevoke {
    pub fn encode(
        &self,
        admin_cap: &Capability,
        relay_service_id: &RelayServiceId,
    ) -> Result<[u8; LEASE_REVOKE_LEN], LeaseCodecError> {
        encode_short(
            OP_REVOKE,
            REVOKE_DOMAIN,
            &self.queue_id,
            self.epoch,
            self.operation_expiry,
            &self.nonce,
            admin_cap,
            relay_service_id,
        )
    }

    pub fn decode_and_verify(
        wire: &[u8],
        admin_cap: &Capability,
        relay_service_id: &RelayServiceId,
        policy: ValidationPolicy,
    ) -> Result<Self, LeaseCodecError> {
        let (queue_id, epoch, operation_expiry, nonce) =
            decode_short(wire, OP_REVOKE, REVOKE_DOMAIN, admin_cap, relay_service_id)?;
        let value = Self {
            queue_id,
            epoch,
            operation_expiry,
            nonce,
        };
        validate_policy(policy)?;
        require_random("nonce", &value.nonce)?;
        policy.validate_expiry(value.operation_expiry)?;
        Ok(value)
    }
}

fn create_mac(
    value: &LeaseCreate,
    relay_service_id: &RelayServiceId,
    grant_cap: &Capability,
) -> Result<Hmac<Sha256>, LeaseCodecError> {
    let mut mac = new_mac(grant_cap)?;
    mac.update(CREATE_DOMAIN);
    mac.update(&[VERSION]);
    mac.update(relay_service_id);
    mac.update(&value.queue_id);
    mac.update(&value.epoch.to_be_bytes());
    mac.update(&[OP_CREATE]);
    mac.update(&value.lease_expiry.to_be_bytes());
    mac.update(&value.queue_cells.to_be_bytes());
    mac.update(&value.queue_bytes.to_be_bytes());
    mac.update(&value.capabilities.push);
    mac.update(&value.capabilities.sub);
    mac.update(&value.capabilities.admin);
    mac.update(&value.nonce);
    mac.update(&(ADMISSION_GRANT_LEN as u16).to_be_bytes());
    mac.update(&value.grant);
    Ok(mac)
}

fn rotate_mac(
    value: &LeaseRotate,
    relay_service_id: &RelayServiceId,
    admin_cap: &Capability,
) -> Result<Hmac<Sha256>, LeaseCodecError> {
    let mut mac = new_mac(admin_cap)?;
    mac.update(ROTATE_DOMAIN);
    mac.update(&[VERSION]);
    mac.update(relay_service_id);
    mac.update(&value.queue_id);
    mac.update(&value.old_epoch.to_be_bytes());
    mac.update(&[OP_ROTATE]);
    mac.update(&value.new_epoch.to_be_bytes());
    mac.update(&value.lease_expiry.to_be_bytes());
    mac.update(&value.new_capabilities.push);
    mac.update(&value.new_capabilities.sub);
    mac.update(&value.new_capabilities.admin);
    mac.update(&value.nonce);
    mac.update(&EMPTY_FIELD);
    Ok(mac)
}

#[allow(clippy::too_many_arguments)]
fn encode_short(
    operation: u8,
    domain: &[u8],
    queue_id: &QueueId,
    epoch: u64,
    expiry: u64,
    nonce: &Nonce,
    key: &Capability,
    relay_service_id: &RelayServiceId,
) -> Result<[u8; LEASE_RENEW_LEN], LeaseCodecError> {
    let mut wire = [0u8; LEASE_RENEW_LEN];
    let mut writer = Writer::new(&mut wire);
    writer.byte(VERSION);
    writer.byte(operation);
    writer.bytes(queue_id);
    writer.u64(epoch);
    writer.u64(expiry);
    writer.bytes(nonce);
    let tag_offset = writer.position();
    let mac = short_mac(
        domain,
        operation,
        queue_id,
        epoch,
        expiry,
        nonce,
        key,
        relay_service_id,
    )?;
    wire[tag_offset..].copy_from_slice(&mac.finalize().into_bytes());
    Ok(wire)
}

fn decode_short(
    wire: &[u8],
    operation: u8,
    domain: &[u8],
    key: &Capability,
    relay_service_id: &RelayServiceId,
) -> Result<(QueueId, u64, u64, Nonce), LeaseCodecError> {
    require_len(wire, LEASE_RENEW_LEN)?;
    require_header(wire[0], wire[1], operation)?;
    let mut reader = Reader::new(&wire[..LEASE_RENEW_LEN - TAG_LEN]);
    reader.byte()?;
    reader.byte()?;
    let queue_id = reader.array()?;
    let epoch = reader.u64()?;
    let expiry = reader.u64()?;
    let nonce = reader.array()?;
    let mac = short_mac(
        domain,
        operation,
        &queue_id,
        epoch,
        expiry,
        &nonce,
        key,
        relay_service_id,
    )?;
    mac.verify_slice(&wire[LEASE_RENEW_LEN - TAG_LEN..])
        .map_err(|_| LeaseCodecError::InvalidMac)?;
    Ok((queue_id, epoch, expiry, nonce))
}

#[allow(clippy::too_many_arguments)]
fn short_mac(
    domain: &[u8],
    operation: u8,
    queue_id: &QueueId,
    epoch: u64,
    expiry: u64,
    nonce: &Nonce,
    key: &Capability,
    relay_service_id: &RelayServiceId,
) -> Result<Hmac<Sha256>, LeaseCodecError> {
    let mut mac = new_mac(key)?;
    mac.update(domain);
    mac.update(&[VERSION]);
    mac.update(relay_service_id);
    mac.update(queue_id);
    mac.update(&epoch.to_be_bytes());
    mac.update(&[operation]);
    mac.update(&expiry.to_be_bytes());
    mac.update(nonce);
    mac.update(&EMPTY_FIELD);
    Ok(mac)
}

fn new_mac(key: &[u8; 32]) -> Result<Hmac<Sha256>, LeaseCodecError> {
    Hmac::<Sha256>::new_from_slice(key).map_err(|_| LeaseCodecError::HmacInitialization)
}

fn require_len(wire: &[u8], expected: usize) -> Result<(), LeaseCodecError> {
    if wire.len() != expected {
        return Err(LeaseCodecError::WrongLength {
            expected,
            actual: wire.len(),
        });
    }
    Ok(())
}

fn require_header(version: u8, operation: u8, expected: u8) -> Result<(), LeaseCodecError> {
    if version != VERSION {
        return Err(LeaseCodecError::InvalidVersion(version));
    }
    if operation != expected {
        return Err(LeaseCodecError::InvalidOperation {
            expected,
            actual: operation,
        });
    }
    Ok(())
}

fn validate_policy(policy: ValidationPolicy) -> Result<(), LeaseCodecError> {
    if policy.clock_skew_secs > MAX_CLOCK_SKEW_SECS {
        return Err(LeaseCodecError::ClockSkewTooLarge(policy.clock_skew_secs));
    }
    Ok(())
}

fn require_random<const N: usize>(
    field: &'static str,
    value: &[u8; N],
) -> Result<(), LeaseCodecError> {
    if value.iter().all(|byte| *byte == 0) {
        return Err(LeaseCodecError::ZeroRandomField(field));
    }
    Ok(())
}

struct Writer<'a> {
    wire: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    fn new(wire: &'a mut [u8]) -> Self {
        Self { wire, position: 0 }
    }

    fn byte(&mut self, value: u8) {
        self.wire[self.position] = value;
        self.position += 1;
    }

    fn bytes(&mut self, value: &[u8]) {
        let end = self.position + value.len();
        self.wire[self.position..end].copy_from_slice(value);
        self.position = end;
    }

    fn u16(&mut self, value: u16) {
        self.bytes(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }

    fn position(&self) -> usize {
        self.position
    }
}

struct Reader<'a> {
    wire: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(wire: &'a [u8]) -> Self {
        Self { wire, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], LeaseCodecError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(LeaseCodecError::WrongLength {
                expected: length,
                actual: self.wire.len().saturating_sub(self.position),
            })?;
        if end > self.wire.len() {
            return Err(LeaseCodecError::WrongLength {
                expected: length,
                actual: self.wire.len().saturating_sub(self.position),
            });
        }
        let value = &self.wire[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, LeaseCodecError> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], LeaseCodecError> {
        self.take(N)?
            .try_into()
            .map_err(|_| LeaseCodecError::WrongLength {
                expected: N,
                actual: 0,
            })
    }

    fn u16(&mut self) -> Result<u16, LeaseCodecError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, LeaseCodecError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
}

/// Fields of an already owner-authenticated retained alias. This is not relay admission.
pub struct RetainedAliasBinding<'a> {
    pub payload: &'a [u8],
    pub relay_service_id: &'a RelayServiceId,
    pub queue_id: QueueId,
    pub epoch: u64,
    pub expiry: u64,
    pub push_cap: Capability,
    pub capabilities: Capabilities,
    pub create_path: &'a str,
    pub limits: LeaseLimits,
}

/// Owner-sealed accepted renewal, not an admission or renewal execution API.
pub fn validate_retained_alias_binding(
    alias: &RetainedAliasBinding<'_>,
    renewal: Option<&[u8]>,
) -> Result<(), LeaseCodecError> {
    let wire = alias.payload;
    let create = LeaseCreate::decode_body(wire)?;
    let grant = AdmissionGrant::decode_body(&create.grant)?;
    let target = alias.relay_service_id;
    if grant.relay_service_id != *target {
        return Err(LeaseCodecError::RelayServiceMismatch);
    }
    if create.queue_id != alias.queue_id || grant.queue_id != create.queue_id {
        return Err(LeaseCodecError::QueueBindingMismatch);
    }
    if create.epoch != alias.epoch || grant.epoch != create.epoch || create.epoch == 0 {
        return Err(LeaseCodecError::EpochBindingMismatch);
    }
    if let Some(wire) = renewal {
        let (queue, epoch, expiry, nonce) = decode_short(
            wire,
            OP_RENEW,
            RENEW_DOMAIN,
            &alias.capabilities.admin,
            target,
        )?;
        require_random("nonce", &nonce)?;
        if queue != create.queue_id
            || epoch != create.epoch
            || expiry != alias.expiry
            || expiry < create.lease_expiry
        {
            return Err(LeaseCodecError::AuthorityBindingMismatch);
        }
    } else if create.lease_expiry != alias.expiry {
        return Err(LeaseCodecError::AuthorityBindingMismatch);
    }
    if create.capabilities != alias.capabilities
        || alias.push_cap != create.capabilities.push
        || alias.create_path != base64ct::Base64UrlUnpadded::encode_string(&grant.grant_cap)
    {
        return Err(LeaseCodecError::AuthorityBindingMismatch);
    }
    if create.queue_cells != alias.limits.max_queue_cells
        || create.queue_bytes != alias.limits.max_queue_bytes
        || create.queue_cells > grant.max_queue_cells
        || create.queue_bytes > grant.max_queue_bytes
        || create.queue_cells == 0
        || create.queue_bytes == 0
    {
        return Err(LeaseCodecError::GrantLimitExceeded);
    }
    if grant.not_before >= grant.expiry {
        return Err(LeaseCodecError::InvalidGrantWindow);
    }
    create.capabilities.validate(&create.queue_id)?;
    require_random("nonce", &create.nonce)?;
    require_random("grant_id", &grant.grant_id)?;
    require_random("grant_cap", &grant.grant_cap)?;
    let mac = create_mac(&create, target, &grant.grant_cap)?;
    mac.verify_slice(&wire[LEASE_CREATE_LEN - TAG_LEN..])
        .map_err(|_| LeaseCodecError::InvalidMac)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADMIT_KEY: AdmissionKey = [0xa1; 32];
    const RELAY_ID: RelayServiceId = [0xb2; 32];

    fn policy() -> ValidationPolicy {
        ValidationPolicy::new(1_000, 0, 5_000).unwrap()
    }

    fn caps(base: u8) -> Capabilities {
        Capabilities {
            push: [base; 32],
            sub: [base + 1; 32],
            admin: [base + 2; 32],
        }
    }

    fn grant() -> AdmissionGrant {
        AdmissionGrant {
            relay_service_id: RELAY_ID,
            grant_id: [3; 16],
            grant_cap: [4; 32],
            queue_id: [5; 32],
            epoch: 7,
            not_before: 900,
            expiry: 1_500,
            max_queue_cells: 64,
            max_queue_bytes: 65_536,
        }
    }

    fn create() -> LeaseCreate {
        LeaseCreate {
            queue_id: [5; 32],
            epoch: 7,
            lease_expiry: 2_000,
            queue_cells: 32,
            queue_bytes: 32_768,
            capabilities: caps(10),
            nonce: [20; 16],
            grant: grant().encode(&ADMIT_KEY).unwrap(),
        }
    }

    #[test]
    fn deterministic_grant_layout_and_authentication() {
        let value = grant();
        let wire = value.encode(&ADMIT_KEY).unwrap();
        assert_eq!(wire.len(), ADMISSION_GRANT_LEN);
        assert_eq!(&wire[0..1], &[VERSION]);
        assert_eq!(&wire[1..33], &RELAY_ID);
        assert_eq!(&wire[33..49], &[3; 16]);
        assert_eq!(&wire[49..81], &[4; 32]);
        assert_eq!(wire[81], OP_CREATE);
        assert_eq!(&wire[82..114], &[5; 32]);
        assert_eq!(&wire[114..122], &7u64.to_be_bytes());
        assert_eq!(&wire[138..140], &64u16.to_be_bytes());
        assert_eq!(&wire[140..148], &65_536u64.to_be_bytes());
        assert_eq!(
            AdmissionGrant::decode_and_verify(&wire, &ADMIT_KEY, &RELAY_ID, policy()).unwrap(),
            value
        );
    }

    #[test]
    fn deterministic_operation_layouts_round_trip() {
        let limits = LeaseLimits {
            max_queue_cells: 128,
            max_queue_bytes: 100_000,
        };
        let create = create();
        let create_wire = create.encode(&RELAY_ID).unwrap();
        assert_eq!(create_wire.len(), LEASE_CREATE_LEN);
        assert_eq!(&create_wire[..2], &[VERSION, OP_CREATE]);
        assert_eq!(
            &create_wire[172..174],
            &(ADMISSION_GRANT_LEN as u16).to_be_bytes()
        );
        assert_eq!(
            LeaseCreate::decode_and_verify(
                &create_wire,
                &ADMIT_KEY,
                &RELAY_ID,
                policy(),
                policy(),
                limits
            )
            .unwrap(),
            create
        );

        let renew = LeaseRenew {
            queue_id: [5; 32],
            epoch: 7,
            lease_expiry: 2_500,
            nonce: [21; 16],
        };
        let renew_wire = renew.encode(&[12; 32], &RELAY_ID).unwrap();
        assert_eq!(renew_wire.len(), LEASE_RENEW_LEN);
        assert_eq!(
            LeaseRenew::decode_and_verify(&renew_wire, &[12; 32], &RELAY_ID, 2_000, policy())
                .unwrap(),
            renew
        );

        let rotate = LeaseRotate {
            queue_id: [5; 32],
            old_epoch: 7,
            new_epoch: 8,
            lease_expiry: 2_500,
            new_capabilities: caps(30),
            nonce: [40; 16],
        };
        let rotate_wire = rotate.encode(&[12; 32], &RELAY_ID).unwrap();
        assert_eq!(rotate_wire.len(), LEASE_ROTATE_LEN);
        assert_eq!(
            LeaseRotate::decode_and_verify(&rotate_wire, &caps(10), &RELAY_ID, policy()).unwrap(),
            rotate
        );

        let revoke = LeaseRevoke {
            queue_id: [5; 32],
            epoch: 8,
            operation_expiry: 1_200,
            nonce: [41; 16],
        };
        let revoke_wire = revoke.encode(&[32; 32], &RELAY_ID).unwrap();
        assert_eq!(revoke_wire.len(), LEASE_REVOKE_LEN);
        assert_eq!(
            LeaseRevoke::decode_and_verify(&revoke_wire, &[32; 32], &RELAY_ID, policy()).unwrap(),
            revoke
        );
    }

    #[test]
    fn relay_context_and_each_tag_are_authenticated() {
        let limits = LeaseLimits {
            max_queue_cells: 128,
            max_queue_bytes: 100_000,
        };
        let wire = create().encode(&RELAY_ID).unwrap();
        assert_eq!(
            LeaseCreate::decode_and_verify(&wire, &ADMIT_KEY, &[9; 32], policy(), policy(), limits),
            Err(LeaseCodecError::RelayServiceMismatch)
        );

        let mut tampered = wire;
        tampered[100] ^= 1;
        assert_eq!(
            LeaseCreate::decode_and_verify(
                &tampered,
                &ADMIT_KEY,
                &RELAY_ID,
                policy(),
                policy(),
                limits
            ),
            Err(LeaseCodecError::InvalidMac)
        );

        let renew = LeaseRenew {
            queue_id: [5; 32],
            epoch: 7,
            lease_expiry: 2_500,
            nonce: [21; 16],
        };
        let mut wire = renew.encode(&[12; 32], &RELAY_ID).unwrap();
        wire[50] ^= 1;
        assert_eq!(
            LeaseRenew::decode_and_verify(&wire, &[12; 32], &RELAY_ID, 2_000, policy()),
            Err(LeaseCodecError::InvalidMac)
        );

        let rotate = LeaseRotate {
            queue_id: [5; 32],
            old_epoch: 7,
            new_epoch: 8,
            lease_expiry: 2_500,
            new_capabilities: caps(30),
            nonce: [40; 16],
        };
        let mut wire = rotate.encode(&[12; 32], &RELAY_ID).unwrap();
        wire[100] ^= 1;
        assert_eq!(
            LeaseRotate::decode_and_verify(&wire, &caps(10), &RELAY_ID, policy()),
            Err(LeaseCodecError::InvalidMac)
        );

        let revoke = LeaseRevoke {
            queue_id: [5; 32],
            epoch: 8,
            operation_expiry: 1_200,
            nonce: [41; 16],
        };
        let mut wire = revoke.encode(&[32; 32], &RELAY_ID).unwrap();
        wire[60] ^= 1;
        assert_eq!(
            LeaseRevoke::decode_and_verify(&wire, &[32; 32], &RELAY_ID, policy()),
            Err(LeaseCodecError::InvalidMac)
        );
    }

    #[test]
    fn rejects_expiry_bindings_limits_and_reused_caps() {
        let expired = ValidationPolicy::new(2_000, 0, 5_000).unwrap();
        let grant_wire = grant().encode(&ADMIT_KEY).unwrap();
        assert!(matches!(
            AdmissionGrant::decode_and_verify(&grant_wire, &ADMIT_KEY, &RELAY_ID, expired),
            Err(LeaseCodecError::Expired { .. })
        ));

        let limits = LeaseLimits {
            max_queue_cells: 128,
            max_queue_bytes: 100_000,
        };
        let mut value = create();
        value.queue_id = [6; 32];
        let wire = value.encode(&RELAY_ID).unwrap();
        assert_eq!(
            LeaseCreate::decode_and_verify(
                &wire,
                &ADMIT_KEY,
                &RELAY_ID,
                policy(),
                policy(),
                limits
            ),
            Err(LeaseCodecError::QueueBindingMismatch)
        );

        let mut value = create();
        value.queue_cells = 65;
        let wire = value.encode(&RELAY_ID).unwrap();
        assert_eq!(
            LeaseCreate::decode_and_verify(
                &wire,
                &ADMIT_KEY,
                &RELAY_ID,
                policy(),
                policy(),
                limits
            ),
            Err(LeaseCodecError::GrantLimitExceeded)
        );

        let mut value = create();
        value.capabilities.sub = value.capabilities.push;
        let wire = value.encode(&RELAY_ID).unwrap();
        assert_eq!(
            LeaseCreate::decode_and_verify(
                &wire,
                &ADMIT_KEY,
                &RELAY_ID,
                policy(),
                policy(),
                limits
            ),
            Err(LeaseCodecError::CapabilitiesNotIndependent)
        );
    }

    #[test]
    fn exact_lengths_reject_truncation_and_trailing_bytes_without_panics() {
        let limits = LeaseLimits {
            max_queue_cells: 128,
            max_queue_bytes: 100_000,
        };
        let create_wire = create().encode(&RELAY_ID).unwrap();
        for length in 0..create_wire.len() {
            assert!(matches!(
                LeaseCreate::decode_and_verify(
                    &create_wire[..length],
                    &ADMIT_KEY,
                    &RELAY_ID,
                    policy(),
                    policy(),
                    limits
                ),
                Err(LeaseCodecError::WrongLength { .. })
            ));
        }

        let renew = LeaseRenew {
            queue_id: [5; 32],
            epoch: 7,
            lease_expiry: 2_500,
            nonce: [21; 16],
        };
        let renew_wire = renew.encode(&[12; 32], &RELAY_ID).unwrap();
        for length in 0..renew_wire.len() {
            assert!(matches!(
                LeaseRenew::decode_and_verify(
                    &renew_wire[..length],
                    &[12; 32],
                    &RELAY_ID,
                    2_000,
                    policy()
                ),
                Err(LeaseCodecError::WrongLength { .. })
            ));
        }

        let rotate = LeaseRotate {
            queue_id: [5; 32],
            old_epoch: 7,
            new_epoch: 8,
            lease_expiry: 2_500,
            new_capabilities: caps(30),
            nonce: [40; 16],
        };
        let rotate_wire = rotate.encode(&[12; 32], &RELAY_ID).unwrap();
        for length in 0..rotate_wire.len() {
            assert!(matches!(
                LeaseRotate::decode_and_verify(
                    &rotate_wire[..length],
                    &caps(10),
                    &RELAY_ID,
                    policy()
                ),
                Err(LeaseCodecError::WrongLength { .. })
            ));
        }

        let revoke = LeaseRevoke {
            queue_id: [5; 32],
            epoch: 8,
            operation_expiry: 1_200,
            nonce: [41; 16],
        };
        let revoke_wire = revoke.encode(&[32; 32], &RELAY_ID).unwrap();
        for length in 0..revoke_wire.len() {
            assert!(matches!(
                LeaseRevoke::decode_and_verify(
                    &revoke_wire[..length],
                    &[32; 32],
                    &RELAY_ID,
                    policy()
                ),
                Err(LeaseCodecError::WrongLength { .. })
            ));
        }
        let mut trailing = create_wire.to_vec();
        trailing.push(0);
        assert!(matches!(
            LeaseCreate::decode_and_verify(
                &trailing,
                &ADMIT_KEY,
                &RELAY_ID,
                policy(),
                policy(),
                limits
            ),
            Err(LeaseCodecError::WrongLength { .. })
        ));

        let grant_wire = grant().encode(&ADMIT_KEY).unwrap();
        for length in 0..grant_wire.len() {
            assert!(matches!(
                AdmissionGrant::decode_and_verify(
                    &grant_wire[..length],
                    &ADMIT_KEY,
                    &RELAY_ID,
                    policy()
                ),
                Err(LeaseCodecError::WrongLength { .. })
            ));
        }
    }
}
