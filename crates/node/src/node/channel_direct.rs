// Split from the former monolithic node.rs on 2026-09-05; no behaviour change.

use super::*;

pub(crate) fn channel_direct_key(
    channel_id: crate::channel::ChannelId,
    own_secret: [u8; 32],
    own_member: [u8; 32],
    peer_member: [u8; 32],
    peer_public: [u8; 32],
) -> Result<[u8; 32], String> {
    if peer_public == [0; 32] || peer_member == own_member {
        return Err("member has no channel-direct capability".into());
    }
    let shared = x25519_dalek::StaticSecret::from(own_secret)
        .diffie_hellman(&x25519_dalek::PublicKey::from(peer_public));
    if shared.as_bytes() == &[0; 32] {
        return Err("invalid channel-direct public key".into());
    }
    let mut context = Vec::with_capacity(96);
    context.extend_from_slice(&channel_id.0);
    if own_member < peer_member {
        context.extend_from_slice(&own_member);
        context.extend_from_slice(&peer_member);
    } else {
        context.extend_from_slice(&peer_member);
        context.extend_from_slice(&own_member);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(&context), shared.as_bytes());
    let mut key = [0; 32];
    hkdf.expand(b"gc1/channel-direct/aead/v1", &mut key)
        .map_err(|_| "channel-direct key derivation failed")?;
    Ok(key)
}

pub(crate) fn seal_channel_direct(
    channel: &str,
    channel_state: &crate::channel::ChannelState,
    recipient: [u8; 32],
    message_id: [u8; 16],
    plaintext: &[u8],
) -> Result<
    (
        crate::channel::ChannelRoute,
        crate::proto::ChannelDirectEnvelope,
    ),
    String,
> {
    let own = channel_state.role.own_pseudonym();
    let route = channel_state
        .directory
        .values()
        .find(|route| route.pseudonym == recipient)
        .cloned()
        .ok_or("unknown channel member")?;
    let mut key = channel_direct_key(
        channel_state.id,
        channel_state.own_route.direct_secret,
        own,
        recipient,
        route.direct_public,
    )?;
    let nonce = random_nonzero();
    let mut envelope = crate::proto::ChannelDirectEnvelope {
        channel: channel.to_string(),
        sender: own,
        recipient,
        message_id,
        nonce,
        ciphertext: Vec::new(),
    };
    let ciphertext = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| "channel-direct key rejected")?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &envelope.aad(),
            },
        )
        .map_err(|_| "channel-direct encryption failed");
    key.fill(0);
    envelope.ciphertext = ciphertext?;
    Ok((route, envelope))
}

pub(crate) struct PreparedChannelDirect {
    message_id: [u8; 16],
    receipt: crate::scheduler::Receipt,
}

impl PreparedChannelDirect {
    pub(crate) async fn complete(self, state: &Arc<Mutex<NodeState>>) -> Result<[u8; 16], String> {
        let result = self.receipt.completion().await.accepted();
        if result.is_err() {
            state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pending_channel_direct
                .remove(&self.message_id);
        }
        result.map(|_| self.message_id)
    }
}

/// Authorize, seal and enqueue while the command's channel ordering lock is held.
/// The resulting receipt owns no channel lock and still means hop acceptance only.
pub(crate) fn prepare_channel_direct(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    channel: &str,
    recipient: [u8; 32],
    text: &[u8],
) -> Result<PreparedChannelDirect, String> {
    validate_application_payload(text)?;
    let application = gcoms_core::is_piece_application_payload(text);
    let message_id = fresh_msg_id();
    let mut plaintext = Vec::with_capacity(9 + text.len());
    plaintext.push(if application { 3 } else { 1 });
    plaintext.extend_from_slice(&now_ms().to_be_bytes());
    plaintext.extend_from_slice(text);
    let envelope_result = {
        let mut state = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !application && state.pending_channel_direct.len() >= 64 {
            return Err("too many unacknowledged channel direct messages".into());
        }
        let channel_state = state.channels.get(channel).ok_or("no channel")?;
        if application
            && !channel_state
                .role
                .roster_members()
                .iter()
                .any(|m| m.pseudonym == recipient)
        {
            return Err("recipient is not a current channel member".into());
        }
        let sealed = seal_channel_direct(channel, channel_state, recipient, message_id, &plaintext);
        if !application && sealed.is_ok() {
            state
                .pending_channel_direct
                .insert(message_id, (channel.to_string(), recipient));
        }
        sealed
    };
    plaintext.fill(0);
    let (route, envelope) = envelope_result?;
    let result = (|| {
        let payload = envelope
            .encode()
            .ok_or("channel-direct envelope too large")?;
        // Keep the same FIFO destination as authenticated directory records.
        let cell = Cell::new(CellType::Msg, 0, 0, payload);
        let class = if application {
            ProducerClass::ChannelData
        } else {
            ProducerClass::ChannelControl
        };
        let receipt = scheduler
            .push(class, route.control, cell)
            .map_err(|error| error.to_string())?;
        Ok(PreparedChannelDirect {
            message_id,
            receipt,
        })
    })();
    if result.is_err() {
        state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pending_channel_direct
            .remove(&message_id);
    }
    result
}

pub(crate) async fn send_channel_direct(
    state: &Arc<Mutex<NodeState>>,
    scheduler: &RelayScheduler,
    channel: &str,
    recipient: [u8; 32],
    text: &[u8],
) -> Result<[u8; 16], String> {
    prepare_channel_direct(state, scheduler, channel, recipient, text)?
        .complete(state)
        .await
}

pub(crate) fn handle_channel_direct(
    state: &Arc<Mutex<NodeState>>,
    encoded: &[u8],
    events: &broadcast::Sender<Ev>,
) {
    let Some(envelope) = crate::proto::ChannelDirectEnvelope::decode(encoded) else {
        return;
    };
    let mut state = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(channel) = state.channels.get_mut(&envelope.channel) else {
        return;
    };
    if envelope.recipient != channel.role.own_pseudonym()
        || channel
            .role
            .roster_members()
            .iter()
            .all(|member| member.pseudonym != envelope.sender)
    {
        return;
    }
    let Some(sender_route) = channel
        .directory
        .values()
        .find(|route| route.pseudonym == envelope.sender)
        .cloned()
    else {
        return;
    };
    let Ok(mut key) = channel_direct_key(
        channel.id,
        channel.own_route.direct_secret,
        envelope.recipient,
        envelope.sender,
        sender_route.direct_public,
    ) else {
        return;
    };
    let Ok(cipher) = Aes256Gcm::new_from_slice(&key) else {
        key.fill(0);
        return;
    };
    let Ok(mut plaintext) = cipher.decrypt(
        Nonce::from_slice(&envelope.nonce),
        Payload {
            msg: &envelope.ciphertext,
            aad: &envelope.aad(),
        },
    ) else {
        key.fill(0);
        return;
    };
    key.fill(0);
    match plaintext.first() {
        Some(1) if plaintext.len() >= 9 => {
            if gcoms_core::is_volatile_application_payload(&plaintext[9..]) {
                plaintext.fill(0);
                return;
            }
            let sent_ms = u64::from_be_bytes(plaintext[1..9].try_into().expect("checked length"));
            let first_sighting = !channel.seen_direct.contains(&envelope.message_id);
            if first_sighting {
                channel.seen_direct.push_back(envelope.message_id);
                while channel.seen_direct.len() > 1024 {
                    channel.seen_direct.pop_front();
                }
            }
            let ack = seal_channel_direct(
                &envelope.channel,
                channel,
                envelope.sender,
                envelope.message_id,
                &[2],
            );
            if let Ok((route, ack)) = ack {
                if let Some(payload) = ack.encode() {
                    let _ = state.scheduler.push(
                        ProducerClass::ChannelControl,
                        route.control,
                        Cell::new(CellType::Msg, 0, 0, payload),
                    );
                }
            }
            if first_sighting {
                let _ = events.send(Ev::ChannelDirectMessage {
                    channel: envelope.channel,
                    sender_member_id: envelope.sender,
                    recipient_member_id: envelope.recipient,
                    msg_id: envelope.message_id,
                    ts_unix: sent_ms / 1000,
                    text: plaintext[9..].to_vec(),
                });
            }
        }
        Some(3)
            if plaintext.len() >= 9
                && gcoms_core::is_piece_application_payload(&plaintext[9..]) =>
        {
            // No text receipt, retained transcript, or unbounded per-message ACK
            // map. The piece protocol re-requests missing data and confirms only
            // verified durable pieces. Authentication and membership are above.
            let sent_ms = u64::from_be_bytes(plaintext[1..9].try_into().expect("checked length"));
            let _ = events.send(Ev::ChannelDirectMessage {
                channel: envelope.channel,
                sender_member_id: envelope.sender,
                recipient_member_id: envelope.recipient,
                msg_id: envelope.message_id,
                ts_unix: sent_ms / 1000,
                text: plaintext[9..].to_vec(),
            });
        }
        Some(&crate::channel::CHANNEL_DIRECT_PEX) => {
            let replay_key = (envelope.sender, envelope.message_id);
            if !channel.seen_pex.contains(&replay_key) {
                if let Some((name, refs, have)) = crate::channel::decode_channel_pex(&plaintext) {
                    if name == envelope.channel
                        && apply_authenticated_pex(channel, envelope.sender, &refs, &have)
                    {
                        channel.seen_pex.push_back(replay_key);
                        while channel.seen_pex.len() > 1024 {
                            channel.seen_pex.pop_front();
                        }
                        metrics::log_event(
                            "chan_pex_received",
                            &[
                                ("channel", name),
                                ("descriptors", refs.len().to_string()),
                                ("have", have.len().to_string()),
                                ("node", short_addr_tag(&info_addr(&state.info))),
                            ],
                        );
                    }
                }
            }
        }
        Some(2) if plaintext.len() == 1 => {
            let matches = state
                .pending_channel_direct
                .get(&envelope.message_id)
                .is_some_and(|(channel, recipient)| {
                    channel == &envelope.channel && recipient == &envelope.sender
                });
            if matches {
                state.pending_channel_direct.remove(&envelope.message_id);
                let _ = events.send(Ev::ChannelDirectDelivery {
                    channel: envelope.channel,
                    recipient_member_id: envelope.sender,
                    msg_id: envelope.message_id,
                });
            }
        }
        _ => {}
    }
    plaintext.fill(0);
}
