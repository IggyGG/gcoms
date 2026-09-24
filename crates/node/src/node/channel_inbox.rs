//! Bounded, sealed channel deliveries. Transport receipts acknowledge this
//! durable handoff; only the local archive owner may consume its records.
use super::Ev;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;

pub const LIMIT: usize = 256;
pub const BYTE_LIMIT: usize = 4 * 1024 * 1024;
const MAX_CURSOR: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Message {
    Channel {
        channel: String,
        id: [u8; 16],
        timestamp: u64,
        sender: String,
        epoch: u64,
        index: u32,
        body: Vec<u8>,
        latency: u64,
    },
    Private {
        channel: String,
        id: [u8; 16],
        timestamp: u64,
        sender: [u8; 32],
        recipient: [u8; 32],
        body: Vec<u8>,
    },
}
impl Message {
    fn key(&self) -> (&str, [u8; 16]) {
        match self {
            Self::Channel { channel, id, .. } | Self::Private { channel, id, .. } => (channel, *id),
        }
    }
    fn body(&self) -> &[u8] {
        match self {
            Self::Channel { body, .. } | Self::Private { body, .. } => body,
        }
    }
    pub fn event(&self) -> Ev {
        match self {
            Self::Channel {
                channel,
                id,
                timestamp,
                sender,
                epoch,
                index,
                body,
                latency,
            } => Ev::ChannelMessage {
                channel: channel.clone(),
                msg_id: *id,
                ts_unix: *timestamp,
                sender: sender.clone(),
                channel_epoch: *epoch,
                sender_index: *index,
                text: body.clone(),
                latency_hint_ms: *latency,
            },
            Self::Private {
                channel,
                id,
                timestamp,
                sender,
                recipient,
                body,
            } => Ev::ChannelDirectMessage {
                channel: channel.clone(),
                msg_id: *id,
                ts_unix: *timestamp,
                sender_member_id: *sender,
                recipient_member_id: *recipient,
                text: body.clone(),
            },
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Delivery {
    pub sequence: u64,
    pub message: Message,
}
impl Delivery {
    pub fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"gcoms/channel-inbox/v1\0");
        hash.update(serde_json::to_vec(self).expect("bounded channel delivery serialization"));
        hash.finalize().into()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Inbox {
    pub enabled: bool,
    next: u64,
    entries: VecDeque<Delivery>,
}
impl Default for Inbox {
    fn default() -> Self {
        Self {
            enabled: false,
            next: 1,
            entries: VecDeque::new(),
        }
    }
}
impl Inbox {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            ..Default::default()
        }
    }
    pub fn stage(&mut self, message: Message) -> Result<(), String> {
        if !self.enabled || gcoms_core::is_piece_application_payload(message.body()) {
            return Ok(());
        }
        let (channel, id) = message.key();
        if channel.is_empty()
            || channel.len() > 256
            || id == [0; 16]
            || message.body().len() > gcoms_core::APPLICATION_PAYLOAD_LIMIT
        {
            return Err("invalid channel delivery".into());
        }
        if let Some(old) = self
            .entries
            .iter()
            .find(|v| v.message.key() == (channel, id))
        {
            return if old.message == message {
                Ok(())
            } else {
                Err("conflicting channel delivery".into())
            };
        }
        if self.entries.len() >= LIMIT || self.next >= MAX_CURSOR {
            return Err("channel archive inbox full".into());
        }
        let item = Delivery {
            sequence: self.next,
            message,
        };
        self.entries.push_back(item);
        if self.encode()?.len() > BYTE_LIMIT {
            self.entries.pop_back();
            return Err("channel archive byte limit".into());
        }
        self.next += 1;
        Ok(())
    }
    pub fn page(&self, after: u64, limit: usize) -> Result<Vec<Delivery>, String> {
        if !self.enabled || limit == 0 || limit > 32 {
            return Err("invalid channel inbox request".into());
        }
        Ok(self
            .entries
            .iter()
            .filter(|v| v.sequence > after)
            .take(limit)
            .cloned()
            .collect())
    }
    pub fn consume(&mut self, sequence: u64, digest: [u8; 32]) -> Result<bool, String> {
        let Some(pos) = self.entries.iter().position(|v| v.sequence == sequence) else {
            return Ok(false);
        };
        if self.entries[pos].digest() != digest {
            return Err("channel inbox receipt mismatch".into());
        }
        self.entries.remove(pos);
        Ok(true)
    }
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| e.to_string())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > BYTE_LIMIT {
            return Err("channel inbox too large".into());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if !value.enabled
            || value.next == 0
            || value.next > MAX_CURSOR
            || value.entries.len() > LIMIT
            || value
                .entries
                .iter()
                .zip(value.entries.iter().skip(1))
                .any(|(a, b)| a.sequence >= b.sequence)
            || value
                .entries
                .iter()
                .any(|v| v.sequence == 0 || v.sequence >= value.next)
        {
            return Err("invalid channel inbox cursor".into());
        }
        let mut checked = Self {
            enabled: true,
            ..Self::default()
        };
        for item in &value.entries {
            checked.stage(item.message.clone())?;
        }
        if checked.entries.len() != value.entries.len() {
            return Err("duplicate channel inbox record".into());
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn message(index: u16) -> Message {
        let mut id = [0; 16];
        id[..2].copy_from_slice(&(index + 1).to_be_bytes());
        Message::Channel {
            channel: "archive".into(),
            id,
            timestamp: 1,
            sender: "peer".into(),
            epoch: 0,
            index: 1,
            body: b"retained plaintext".to_vec(),
            latency: 0,
        }
    }
    #[test]
    fn bounded_inbox_never_consumes_on_observation_or_wrong_receipt() {
        let mut inbox = Inbox::new(true);
        for n in 0..LIMIT {
            inbox.stage(message(n as u16)).unwrap();
        }
        let before = inbox.encode().unwrap();
        assert!(inbox.stage(message(LIMIT as u16)).is_err());
        assert_eq!(before, inbox.encode().unwrap());
        let first = inbox.page(0, 1).unwrap().remove(0);
        assert_eq!(inbox.page(0, 1).unwrap()[0], first);
        assert!(inbox.consume(first.sequence, [0; 32]).is_err());
        assert_eq!(before, inbox.encode().unwrap());
        assert!(inbox.consume(first.sequence, first.digest()).unwrap());
        inbox.stage(message(LIMIT as u16)).unwrap();
        let restored = Inbox::decode(&inbox.encode().unwrap()).unwrap();
        assert_eq!(restored.page(0, 32).unwrap(), inbox.page(0, 32).unwrap());
    }
    #[test]
    fn rejects_ambiguous_cursors_and_excess_bytes() {
        let mut inbox = Inbox::new(true);
        inbox.stage(message(0)).unwrap();
        inbox.next = 1;
        assert!(Inbox::decode(&inbox.encode().unwrap()).is_err());
        assert!(Inbox::decode(&vec![0; BYTE_LIMIT + 1]).is_err());
    }
}
