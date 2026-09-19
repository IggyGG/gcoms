//! This format contains capabilities. The caller must authenticate and encrypt
//! it before storage; it is not a network bootstrap or an encrypted file format.
use super::*;

impl View {
    pub(super) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut bytes = Zeroizing::new(b"GCDR\x02".to_vec());
        bytes.push(self.relays.len() as u8);
        for relay in &self.relays {
            bytes.extend_from_slice(relay.encode()?.as_ref());
        }
        bytes.push(self.guards.len() as u8);
        for pin in &self.guards {
            bytes.extend_from_slice(pin);
        }
        bytes.push(self.own.len() as u8);
        for (addr, pin) in &self.own {
            bytes.extend_from_slice(&encode_address(*addr));
            bytes.extend_from_slice(pin);
        }
        Ok(bytes)
    }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let value = self.0.get(..count).ok_or("truncated GC/2 directory")?;
        self.0 = &self.0[count..];
        Ok(value)
    }
    fn count(&mut self, maximum: usize) -> Result<usize> {
        let count = usize::from(self.take(1)?[0]);
        if count > maximum {
            return Err("GC/2 directory count exceeds bound".into());
        }
        Ok(count)
    }
}

impl Directory {
    /// Exports secret routing state, including retained guards and own-service
    /// exclusions. Encrypt and authenticate the bytes before saving them.
    pub fn encode_private(&self) -> Result<Zeroizing<Vec<u8>>> {
        let view = self.view.read().unwrap_or_else(|p| p.into_inner());
        self.check_persistence()?;
        view.encode()
    }

    /// Restores production address policy and exact authenticated expiries.
    /// Stale introductions remain seeds only. A backward clock jump that puts
    /// saved authority more than 24 hours ahead fails closed.
    pub fn restore_private(bytes: &[u8], now: u64) -> Result<Self> {
        Self::restore_with_policy(
            bytes,
            now,
            Arc::new(|addr| crate::service::public_ip(addr.ip())),
        )
    }

    pub(super) fn restore_with_policy(
        bytes: &[u8],
        now: u64,
        allowed: AddressPolicy,
    ) -> Result<Self> {
        if !(8..=MAX_PRIVATE_BYTES).contains(&bytes.len()) {
            return Err("GC/2 directory size exceeds bounds".into());
        }
        let mut input = Reader(bytes);
        if input.take(5)? != b"GCDR\x02" {
            return Err("private GC/2 directory required".into());
        }
        let directory = Self::with_address_policy(allowed);
        let mut view = View::default();
        for _ in 0..input.count(MAX_RELAYS)? {
            let relay = Introduction::decode(input.take(INTRODUCTION_BYTES)?)?;
            directory.admissible(&relay, now)?;
            if view
                .relays
                .iter()
                .any(|old| old.service_id == relay.service_id)
            {
                return Err("duplicate private GC/2 relay".into());
            }
            view.relays.push(relay);
        }
        for _ in 0..input.count(MAX_GUARDS)? {
            view.guards.push(input.take(32)?.try_into()?);
        }
        for _ in 0..input.count(MAX_OWN_SERVICES)? {
            let addr = decode_address(input.take(19)?)?;
            let pin = input.take(32)?.try_into()?;
            if pin == [0; 32] || view.own.contains(&(addr, pin)) {
                return Err("invalid private GC/2 own service".into());
            }
            view.own.push((addr, pin));
        }
        if !input.0.is_empty() {
            return Err("trailing private GC/2 directory bytes".into());
        }
        Self::validate_guards(&view, &view.guards)?;
        *directory.view.write().unwrap_or_else(|p| p.into_inner()) = view;
        Ok(directory)
    }
}
