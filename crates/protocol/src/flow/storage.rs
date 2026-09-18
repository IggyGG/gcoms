use super::*;

const MAGIC: &[u8; 5] = b"GCW2\x01";
/// At most 63 retained packets and 63 small receive/credit records.
pub const MAX_PRIVATE_BYTES: usize = 128 + (MAX_MESSAGE + 43 + 153) * COUNTER_WINDOW as usize;

impl Window {
    /// Secret material: store only inside an authenticated encrypted archive,
    /// atomically with the corresponding ratchet and application state.
    pub fn encode_private(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::new());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.session);
        for value in [
            self.sent,
            self.credited.floor,
            self.credited.mask,
            self.received.floor,
            self.received.mask,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.push(self.tx.len() as u8);
        for entry in self.tx.values() {
            out.push(entry.purpose as u8);
            out.extend_from_slice(&entry.sent_unix.to_be_bytes());
            out.extend_from_slice(&entry.authority.secret.0);
            out.extend_from_slice(&(entry.packet.len() as u16).to_be_bytes());
            out.extend_from_slice(&entry.packet);
        }
        out.push(self.rx.len() as u8);
        for (counter, entry) in &self.rx {
            out.extend_from_slice(&counter.to_be_bytes());
            out.extend_from_slice(&entry.authority.packet_hash);
            out.extend_from_slice(&entry.authority.secret.0);
            match entry.cached_credit {
                None => out.push(0),
                Some(bytes) => {
                    out.push(1);
                    out.extend_from_slice(&bytes);
                }
            }
        }
        out
    }

    /// Decode only bytes already authenticated by the enclosing archive. Bounds
    /// and canonical state invariants are still checked before allocation/use.
    pub fn decode_private(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_PRIVATE_BYTES {
            return Err(Error::Length);
        }
        let mut input = Input { bytes, cursor: 0 };
        if input.take(5)? != MAGIC {
            return Err(Error::Version);
        }
        let mut window = Self::new(input.array()?)?;
        window.sent = input.u64()?;
        window.credited = Coverage {
            floor: input.u64()?,
            mask: input.u64()?,
        };
        window.received = Coverage {
            floor: input.u64()?,
            mask: input.u64()?,
        };
        let tx_count = input.byte()? as u64;
        if !window.credited.valid()
            || !window.received.valid()
            || window.credited.highest()? > window.sent
            || window.sent.checked_sub(window.credited.floor) != Some(tx_count)
            || tx_count > COUNTER_WINDOW
        {
            return Err(Error::State);
        }
        for index in 0..tx_count {
            let counter = window.credited.floor + index + 1;
            let purpose = Purpose::decode(input.byte()?)?;
            let sent_unix = input.u64()?;
            if sent_unix == 0 {
                return Err(Error::State);
            }
            let secret = Secret(input.array()?);
            let length = u16::from_be_bytes(input.array()?) as usize;
            if length == 0 || length > MAX_MESSAGE {
                return Err(Error::Length);
            }
            let packet = input.take(length)?;
            let authority = Authority::new(&window.session, Sha256::digest(packet).into(), secret);
            if window
                .tx
                .values()
                .any(|entry| entry.authority.reference == authority.reference)
            {
                return Err(Error::State);
            }
            window.tx.insert(
                counter,
                Sent {
                    authority,
                    packet: Arc::new(Zeroizing::new(packet.to_vec())),
                    purpose,
                    sent_unix,
                },
            );
        }
        let rx_count = input.byte()? as usize;
        if rx_count > COUNTER_WINDOW as usize {
            return Err(Error::State);
        }
        let highest = window.received.highest()?;
        let minimum = highest.saturating_sub(COUNTER_WINDOW - 1).max(1);
        let mut previous = 0;
        for _ in 0..rx_count {
            let counter = input.u64()?;
            if counter < minimum
                || counter > highest
                || counter <= previous
                || !window.received.contains(counter)
            {
                return Err(Error::State);
            }
            previous = counter;
            let packet_hash = input.array()?;
            let secret = Secret(input.array()?);
            let authority = Authority::new(&window.session, packet_hash, secret);
            let cached_credit = match input.byte()? {
                0 => None,
                1 => {
                    let bytes: [u8; CREDIT_BYTES] = input.array()?;
                    let prior = decode_credit(&window.session, &authority, &bytes)?;
                    if prior.floor > window.received.floor
                        || prior.highest()? > highest
                        || !prior.contains(counter)
                    {
                        return Err(Error::State);
                    }
                    for shift in 0..COUNTER_WINDOW {
                        if prior.mask & (1 << shift) != 0
                            && !window.received.contains(prior.floor + shift + 1)
                        {
                            return Err(Error::State);
                        }
                    }
                    Some(bytes)
                }
                _ => return Err(Error::State),
            };
            window.rx.insert(
                counter,
                Received {
                    authority,
                    cached_credit,
                },
            );
        }
        // Coverage cannot claim a packet whose receipt authority was discarded
        // inside the still-required receive horizon.
        if highest > 0 {
            for counter in minimum..=highest {
                if window.received.contains(counter) != window.rx.contains_key(&counter) {
                    return Err(Error::State);
                }
            }
        }
        if input.cursor != bytes.len() {
            return Err(Error::Length);
        }
        Ok(window)
    }
}

struct Input<'a> {
    bytes: &'a [u8],
    cursor: usize,
}
impl<'a> Input<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.cursor.checked_add(length).ok_or(Error::Length)?;
        let bytes = self.bytes.get(self.cursor..end).ok_or(Error::Length)?;
        self.cursor = end;
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Length)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
}
