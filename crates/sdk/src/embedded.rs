use crate::ChannelChange;
use crate::{
    ActivityBucket, AutomaticJoinEndpoint, Blob, ChannelId, ChannelMemberSummary, ChannelRole,
    ChannelStatus, ChannelVisibility, ClientEvent, ContactCard, GcClient, Identity, JoinRequest,
    JoinedChannel, MessageId, PresenceMode, PublicChannelDescriptor, Reachability, SdkError,
};
use async_trait::async_trait;
use gcoms_node::node::{Ev, NodeHandle};
use gcoms_node::proto::{b64_info, info_from_b64};
use tokio::sync::{broadcast, mpsc};

async fn forward_events(mut source: broadcast::Receiver<Ev>, sender: mpsc::Sender<ClientEvent>) {
    loop {
        let received = tokio::select! {
            biased;
            _ = sender.closed() => break,
            event = source.recv() => event,
        };
        let event = match received {
            Ok(event) => event.into(),
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                ClientEvent::EventsLagged { skipped }
            }
            Err(broadcast::error::RecvError::Closed) => break,
        };
        if sender.send(event).await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod forwarding_cleanup_tests {
    use super::*;
    #[tokio::test]
    async fn quiet_upstream_is_released_when_downstream_closes() {
        let (upstream, source) = broadcast::channel(2);
        let (sender, receiver) = mpsc::channel(2);
        let task = tokio::spawn(forward_events(source, sender));
        assert_eq!(upstream.receiver_count(), 1);
        drop(receiver);
        tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(upstream.receiver_count(), 0);
    }
}

#[derive(Clone)]
pub struct EmbeddedClient {
    node: NodeHandle,
}

impl EmbeddedClient {
    pub fn new(node: NodeHandle) -> Self {
        Self { node }
    }

    pub fn node(&self) -> &NodeHandle {
        &self.node
    }

    fn parse_card(card: &ContactCard) -> Result<gcoms_node::proto::NodeInfo, SdkError> {
        let encoded = std::str::from_utf8(&card.0).map_err(|_| SdkError::InvalidContactCard)?;
        info_from_b64(encoded).ok_or(SdkError::InvalidContactCard)
    }
}

#[async_trait]
impl GcClient for EmbeddedClient {
    async fn create_channel_invitation(
        &self,
        channel: &str,
        ttl_secs: u64,
    ) -> Result<crate::ChannelInvitation, SdkError> {
        let (id, secret, expiry) = self
            .node
            .create_channel_invite(channel, ttl_secs)
            .await
            .map_err(SdkError::Runtime)?;
        let invite = gcoms_node::channel_invite::ChannelInvite {
            owner: self.node.current_info().await.map_err(SdkError::Runtime)?,
            channel: channel.into(),
            id,
            secret,
            expiry,
        };
        let link = self
            .node
            .channel_invite_link(&invite)
            .map_err(SdkError::Runtime)?;
        self.inspect_channel_invitation(&link).await
    }
    async fn inspect_channel_invitation(
        &self,
        link: &str,
    ) -> Result<crate::ChannelInvitation, SdkError> {
        let envelope = gcoms_node::channel_invite::InviteEnvelope::from_link(link.trim())
            .ok_or_else(|| SdkError::Protocol("invalid channel invitation".into()))?;
        let invite = envelope.invite;
        Ok(crate::ChannelInvitation {
            link: link.trim().into(),
            channel: invite.channel,
            expires_at: invite.expiry,
            local_only: invite.owner.aliases.iter().all(|a| {
                a.target.address.ip().is_loopback() || a.target.address.ip().is_unspecified()
            }),
        })
    }
    async fn join_channel_invitation(
        &self,
        link: &str,
        display: &str,
        timeout_secs: u64,
    ) -> Result<String, SdkError> {
        let envelope = gcoms_node::channel_invite::InviteEnvelope::from_link(link.trim())
            .ok_or_else(|| SdkError::Protocol("invalid channel invitation".into()))?;
        let invite = envelope.invite.clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let remaining = invite.expiry.saturating_sub(now).min(timeout_secs).min(600);
        if remaining == 0 {
            return Err(SdkError::Protocol(
                "invite expired or join deadline elapsed".into(),
            ));
        }
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(remaining);
        tokio::time::timeout_at(deadline, async {
            self.node.install_invite_bootstrap(&envelope).await?;
            self.node.wait_for_inbox(deadline).await?;
            let request = self.node.prepare_channel_join(display).await?;
            let package = self.node.channel_key_package(request).await?;
            let welcome = self
                .node
                .redeem_invite_remote(
                    invite.owner,
                    &invite.channel,
                    display,
                    &package,
                    invite.id,
                    invite.secret,
                    deadline
                        .saturating_duration_since(tokio::time::Instant::now())
                        .as_secs(),
                )
                .await?;
            self.node
                .join_channel(
                    request,
                    &invite.channel,
                    gcoms_node::channel::ChannelVisibility::Private,
                    &welcome,
                )
                .await?;
            Ok::<_, String>(invite.channel)
        })
        .await
        .map_err(|_| SdkError::Runtime("invite join deadline elapsed".into()))?
        .map_err(SdkError::Runtime)
    }

    async fn configure_catalog_origins(&self, origins: Vec<String>) -> Result<(), SdkError> {
        self.node
            .configure_catalog_origins(origins)
            .map_err(SdkError::Runtime)
    }

    async fn catalog_request(
        &self,
        request: crate::CatalogHttpRequest,
    ) -> Result<crate::CatalogHttpResponse, SdkError> {
        request.validate_size()?;
        let (status, body) = self
            .node
            .catalog_request(&request.method, &request.url, &request.body)
            .await
            .map_err(SdkError::Runtime)?;
        Ok(crate::CatalogHttpResponse { status, body })
    }
    async fn file_route(&self) -> Result<Vec<u8>, SdkError> {
        let info = self.node.current_info().await.map_err(SdkError::Runtime)?;
        let a = info
            .primary()
            .ok_or_else(|| SdkError::Runtime("no current file route".into()))?;
        gcoms_core::file_stream::Contact {
            address: a.target.address,
            relay_service_id: a.target.relay_service_id,
            queue_id: a.queue_id,
            epoch: a.epoch,
            push_cap: a.push_cap,
            lease_expiry: a.expiry,
        }
        .encode()
        .map(|bytes| bytes.to_vec())
        .map_err(|e| SdkError::Runtime(e.to_string()))
    }

    fn contact_identity(&self, card: &ContactCard) -> Result<Vec<u8>, SdkError> {
        Ok(Self::parse_card(card)?.identity_pk)
    }
    fn identity(&self) -> Identity {
        Identity {
            contact_card: ContactCard(b64_info(&self.node.info).into_bytes()),
            safety_number: self.node.safety_number.clone(),
        }
    }

    async fn refresh_identity(&self) -> Result<Identity, SdkError> {
        Ok(Identity {
            contact_card: ContactCard(
                b64_info(&self.node.current_info().await.map_err(SdkError::Runtime)?).into_bytes(),
            ),
            safety_number: self.node.safety_number.clone(),
        })
    }

    async fn sign_identity_digest(&self, digest: [u8; 32]) -> Result<Vec<u8>, SdkError> {
        self.node
            .sign_identity_digest(digest)
            .await
            .map_err(SdkError::Runtime)
    }

    async fn sign_principal_binding_hash(
        &self,
        claims_hash: [u8; 32],
    ) -> Result<Vec<u8>, SdkError> {
        self.node
            .sign_principal_binding_hash(claims_hash)
            .await
            .map_err(SdkError::Runtime)
    }

    fn subscribe_events(&self) -> mpsc::Receiver<ClientEvent> {
        let (sender, receiver) = mpsc::channel(256);
        tokio::spawn(forward_events(self.node.subscribe(), sender));
        receiver
    }

    async fn list_channels(&self) -> Result<Vec<JoinedChannel>, SdkError> {
        self.node
            .list_channels()
            .await
            .map(|channels| {
                channels
                    .into_iter()
                    .map(|channel| JoinedChannel {
                        id: ChannelId(channel.id.0),
                        channel: channel.channel,
                        visibility: match channel.visibility {
                            gcoms_node::channel::ChannelVisibility::Public => {
                                ChannelVisibility::Public
                            }
                            gcoms_node::channel::ChannelVisibility::Private => {
                                ChannelVisibility::Private
                            }
                        },
                        status: match channel.status {
                            gcoms_node::node::ChannelStatus::Active => ChannelStatus::Active,
                            gcoms_node::node::ChannelStatus::MembershipPending => {
                                ChannelStatus::MembershipPending
                            }
                        },
                        role: match channel.role {
                            gcoms_node::node::ChannelViewRole::Owner => ChannelRole::Owner,
                            gcoms_node::node::ChannelViewRole::Member => ChannelRole::Member,
                        },
                        epoch: channel.epoch,
                    })
                    .collect()
            })
            .map_err(SdkError::Runtime)
    }

    async fn channel_roster(&self, channel: &str) -> Result<Vec<ChannelMemberSummary>, SdkError> {
        self.node
            .channel_roster(channel)
            .await
            .map(|members| {
                members
                    .into_iter()
                    .map(|member| ChannelMemberSummary {
                        member_id: member.member_id,
                        display_name: member.display_name,
                        is_self: member.is_self,
                        join_order: member.join_order,
                        joined_at_unix: member.joined_at_unix,
                    })
                    .collect()
            })
            .map_err(SdkError::Runtime)
    }

    async fn channel_topic(&self, channel: &str) -> Result<String, SdkError> {
        self.node
            .list_channels()
            .await
            .map_err(SdkError::Runtime)?
            .into_iter()
            .find(|c| c.channel == channel)
            .map(|c| c.topic)
            .ok_or_else(|| SdkError::Runtime("no channel".into()))
    }
    async fn change_channel(
        &self,
        channel: &str,
        change: ChannelChange,
    ) -> Result<MessageId, SdkError> {
        let change = match change {
            ChannelChange::Topic(text) => gcoms_node::channel::ChannelChange::Topic(text),
            ChannelChange::Nickname(text) => gcoms_node::channel::ChannelChange::Nickname(text),
            ChannelChange::Transfer(member) => gcoms_node::channel::ChannelChange::Transfer(member),
            ChannelChange::Leave => gcoms_node::channel::ChannelChange::Leave,
            ChannelChange::Close => gcoms_node::channel::ChannelChange::Close,
        };
        self.node
            .change_channel(channel, change)
            .await
            .map(MessageId)
            .map_err(SdkError::Runtime)
    }

    async fn public_channel_descriptor(
        &self,
        channel: &str,
        description: &str,
        activity: ActivityBucket,
        automatic_join: AutomaticJoinEndpoint,
        expires_at_unix: u64,
    ) -> Result<PublicChannelDescriptor, SdkError> {
        let descriptor = self
            .node
            .public_channel_descriptor(
                channel,
                description,
                match activity {
                    ActivityBucket::None => gcoms_node::channel::ActivityBucket::None,
                    ActivityBucket::Today => gcoms_node::channel::ActivityBucket::Today,
                    ActivityBucket::ThisWeek => gcoms_node::channel::ActivityBucket::ThisWeek,
                    ActivityBucket::Older => gcoms_node::channel::ActivityBucket::Older,
                },
                gcoms_node::channel::AutomaticJoinEndpoint {
                    catalog: automatic_join.catalog,
                    endpoint: automatic_join.endpoint,
                },
                expires_at_unix,
            )
            .await
            .map_err(SdkError::Runtime)?;
        Ok(PublicChannelDescriptor {
            version: descriptor.version,
            expires_at_unix: descriptor.expires_at_unix,
            channel_id: ChannelId(descriptor.channel_id.0),
            owner_public_key: descriptor.owner_public_key,
            capacity: descriptor.capacity,
            title: descriptor.title,
            description: descriptor.description,
            activity,
            automatic_join: AutomaticJoinEndpoint {
                catalog: descriptor.automatic_join.catalog,
                endpoint: descriptor.automatic_join.endpoint,
            },
            signature: descriptor.signature,
        })
    }

    async fn send_direct(
        &self,
        peer: &ContactCard,
        body: &[u8],
        via: Option<&ContactCard>,
    ) -> Result<(), SdkError> {
        crate::types::validate_application_payload(body)?;
        let peer = Self::parse_card(peer)?;
        let via = via.map(Self::parse_card).transpose()?;
        self.node
            .send_1to1(&peer, body, via)
            .await
            .map_err(SdkError::Runtime)
    }

    async fn send_direct_tracked(
        &self,
        peer: &ContactCard,
        body: &[u8],
        via: Option<&ContactCard>,
    ) -> Result<MessageId, SdkError> {
        crate::types::validate_application_payload(body)?;
        let peer = Self::parse_card(peer)?;
        let via = via.map(Self::parse_card).transpose()?;
        self.node
            .send_1to1_tracked(&peer, body, via)
            .await
            .map(MessageId)
            .map_err(SdkError::SendUncertain)
    }

    async fn submit_volatile_opaque(
        &self,
        recipient: &ContactCard,
        content_type: &str,
        body: &[u8],
    ) -> Result<(), SdkError> {
        let peer = Self::parse_card(recipient)?;
        let application = zeroize::Zeroizing::new(crate::ApplicationMessage {
            content_type: content_type.into(),
            body: body.to_vec(),
        });
        let encoded = zeroize::Zeroizing::new(application.encode()?);
        self.node
            .send_volatile_application(&peer, &encoded)
            .await
            .map_err(SdkError::Runtime)
    }

    async fn submit_durable_opaque(
        &self,
        recipient: &ContactCard,
        content_type: &str,
        body: &[u8],
    ) -> Result<(), SdkError> {
        let peer = Self::parse_card(recipient)?;
        let encoded = crate::ApplicationMessage {
            content_type: content_type.into(),
            body: body.to_vec(),
        }
        .encode()?;
        self.node
            .send_durable_1to1(&peer, &encoded, None)
            .await
            .map_err(SdkError::Runtime)
    }

    async fn submit_durable_opaque_class(
        &self,
        recipient: &ContactCard,
        content_type: &str,
        body: &[u8],
        class: gcoms_core::TrafficClass,
    ) -> Result<(), SdkError> {
        let peer = Self::parse_card(recipient)?;
        let encoded = crate::ApplicationMessage {
            content_type: content_type.into(),
            body: body.to_vec(),
        }
        .encode()?;
        self.node
            .send_durable_1to1_class(&peer, &encoded, None, Some(class))
            .await
            .map_err(SdkError::Runtime)
    }

    async fn submit_local_component(&self, wire: &[u8]) -> Result<(), SdkError> {
        self.node
            .submit_local_component(wire)
            .await
            .map_err(SdkError::Runtime)
    }

    async fn application_inbox(
        &self,
        after: u64,
        limit: u16,
    ) -> Result<Vec<crate::ApplicationDelivery>, SdkError> {
        self.node
            .application_inbox(after, usize::from(limit))
            .await
            .map(|entries| {
                entries
                    .iter()
                    .map(|entry| crate::ApplicationDelivery {
                        source_component: None,
                        destination_component: None,
                        sequence: entry.sequence,
                        peer_identity: entry.peer_identity.clone(),
                        message_id: entry.message_id,
                        received_at_unix: entry.received_at_unix,
                        body: entry.body.clone(),
                        receipt_digest: entry.digest(),
                    })
                    .collect()
            })
            .map_err(SdkError::Runtime)
    }

    async fn commit_application(&self, sequence: u64, digest: [u8; 32]) -> Result<(), SdkError> {
        self.node
            .commit_application(sequence, digest)
            .await
            .map_err(SdkError::Runtime)
    }

    async fn set_direct_presence(
        &self,
        peer: &ContactCard,
        mode: PresenceMode,
        lease_secs: u32,
        via: Option<&ContactCard>,
    ) -> Result<(), SdkError> {
        let peer = Self::parse_card(peer)?;
        let via = via.map(Self::parse_card).transpose()?;
        let mode = match mode {
            PresenceMode::RecentlyReachable => gcoms_node::proto::PresenceMode::RecentlyReachable,
            PresenceMode::Away => gcoms_node::proto::PresenceMode::Away,
            PresenceMode::Invisible => gcoms_node::proto::PresenceMode::Invisible,
        };
        self.node
            .send_direct_presence(&peer, mode, lease_secs, via)
            .await
            .map_err(SdkError::Runtime)
    }

    async fn set_direct_presence_opt_in(
        &self,
        peer: &ContactCard,
        enabled: bool,
        via: Option<&ContactCard>,
    ) -> Result<(), SdkError> {
        let peer = Self::parse_card(peer)?;
        let via = via.map(Self::parse_card).transpose()?;
        self.node
            .set_direct_presence_opt_in(&peer, enabled, via)
            .await
            .map_err(SdkError::Runtime)
    }

    async fn create_channel(
        &self,
        channel: &str,
        display_name: &str,
        capacity: usize,
        visibility: ChannelVisibility,
    ) -> Result<ChannelId, SdkError> {
        self.node
            .create_channel(
                channel,
                display_name,
                capacity,
                match visibility {
                    ChannelVisibility::Public => gcoms_node::channel::ChannelVisibility::Public,
                    ChannelVisibility::Private => gcoms_node::channel::ChannelVisibility::Private,
                },
            )
            .await
            .map(|id| ChannelId(id.0))
            .map_err(SdkError::Runtime)
    }

    async fn prepare_channel_join(&self, display_name: &str) -> Result<JoinRequest, SdkError> {
        self.node
            .prepare_channel_join(display_name)
            .await
            .map(JoinRequest)
            .map_err(SdkError::Runtime)
    }

    async fn channel_key_package(&self, request: JoinRequest) -> Result<Blob, SdkError> {
        self.node
            .channel_key_package(request.0)
            .await
            .map(Blob)
            .map_err(SdkError::Runtime)
    }

    async fn admit_channel(
        &self,
        channel: &str,
        key_package: &Blob,
        member_name: &str,
    ) -> Result<Blob, SdkError> {
        self.node
            .admit_channel(channel, &key_package.0, member_name)
            .await
            .map(Blob)
            .map_err(SdkError::Runtime)
    }

    async fn recover_channel_route(
        &self,
        channel: &str,
        expected_channel_id: ChannelId,
        expected_epoch: u64,
        retained_welcome: &Blob,
        peer: &ContactCard,
    ) -> Result<MessageId, SdkError> {
        let peer = Self::parse_card(peer)?;
        self.node
            .recover_channel_route(
                channel,
                gcoms_node::channel::ChannelId(expected_channel_id.0),
                expected_epoch,
                &retained_welcome.0,
                &peer,
            )
            .await
            .map(MessageId)
            .map_err(SdkError::Runtime)
    }

    async fn join_channel(
        &self,
        request: JoinRequest,
        channel: &str,
        visibility: ChannelVisibility,
        welcome: &Blob,
    ) -> Result<(), SdkError> {
        self.node
            .join_channel(
                request.0,
                channel,
                match visibility {
                    ChannelVisibility::Public => gcoms_node::channel::ChannelVisibility::Public,
                    ChannelVisibility::Private => gcoms_node::channel::ChannelVisibility::Private,
                },
                &welcome.0,
            )
            .await
            .map_err(SdkError::Runtime)
    }

    async fn send_channel(&self, channel: &str, body: &[u8]) -> Result<(), SdkError> {
        crate::types::validate_application_payload(body)?;
        self.node
            .send_channel_text(channel, body)
            .await
            .map_err(SdkError::Runtime)
    }

    async fn send_channel_tracked(
        &self,
        channel: &str,
        body: &[u8],
    ) -> Result<MessageId, SdkError> {
        crate::types::validate_application_payload(body)?;
        self.node
            .send_channel_text_tracked(channel, body)
            .await
            .map(MessageId)
            .map_err(SdkError::SendUncertain)
    }

    async fn set_channel_presence(
        &self,
        channel: &str,
        mode: PresenceMode,
        lease_secs: u32,
    ) -> Result<(), SdkError> {
        let mode = match mode {
            PresenceMode::RecentlyReachable => gcoms_node::proto::PresenceMode::RecentlyReachable,
            PresenceMode::Away => gcoms_node::proto::PresenceMode::Away,
            PresenceMode::Invisible => gcoms_node::proto::PresenceMode::Invisible,
        };
        self.node
            .send_channel_presence(channel, mode, lease_secs)
            .await
            .map_err(SdkError::Runtime)
    }

    async fn set_channel_presence_opt_in(
        &self,
        channel: &str,
        enabled: bool,
    ) -> Result<(), SdkError> {
        self.node
            .set_channel_presence_opt_in(channel, enabled)
            .await
            .map_err(SdkError::Runtime)
    }

    async fn send_channel_direct(
        &self,
        channel: &str,
        recipient_member_id: [u8; 32],
        body: &[u8],
    ) -> Result<MessageId, SdkError> {
        crate::types::validate_application_payload(body)?;
        self.node
            .send_channel_direct(channel, recipient_member_id, body)
            .await
            .map(MessageId)
            .map_err(SdkError::Runtime)
    }

    async fn remove_channel_member(
        &self,
        channel: &str,
        member_id: [u8; 32],
    ) -> Result<(), SdkError> {
        self.node
            .remove_channel_member(channel, member_id)
            .await
            .map_err(SdkError::Runtime)
    }
}

impl From<Ev> for ClientEvent {
    fn from(event: Ev) -> Self {
        match event {
            Ev::IdentityUpdated { info, generation } => Self::IdentityUpdated {
                identity: Identity {
                    contact_card: ContactCard(b64_info(&info).into_bytes()),
                    safety_number: gcoms_crypto::safety_number_of(&info.identity_pk),
                },
                generation,
            },
            Ev::SessionOpened {
                peer_pk,
                safety_number,
            } => Self::SessionOpened {
                peer_identity: peer_pk,
                safety_number,
            },
            Ev::VolatileApplication {
                peer_pk,
                msg_id,
                ts_unix,
                body,
            } => Self::VolatileApplication {
                source_component: None,
                destination_component: None,
                peer_identity: peer_pk,
                message_id: MessageId(msg_id),
                timestamp_unix: ts_unix,
                body,
            },
            Ev::Message {
                peer_pk,
                msg_id,
                ts_unix,
                text,
                latency_hint_ms,
            } => Self::DirectMessage {
                peer_identity: peer_pk,
                message_id: MessageId(msg_id),
                timestamp_unix: ts_unix,
                body: text,
                latency_hint_ms,
            },
            Ev::DirectDelivery { peer_pk, msg_id } => Self::DirectDelivered {
                peer_identity: peer_pk,
                message_id: MessageId(msg_id),
            },
            Ev::PresenceChanged {
                peer_pk,
                reachability,
            } => Self::PresenceChanged {
                peer_identity: peer_pk,
                reachability: match reachability {
                    gcoms_node::node::Reachability::RecentlyReachable => {
                        Reachability::RecentlyReachable
                    }
                    gcoms_node::node::Reachability::Away => Reachability::Away,
                    gcoms_node::node::Reachability::Unknown => Reachability::Unknown,
                },
            },
            Ev::ChannelPresenceChanged {
                channel,
                member_id,
                reachability,
            } => Self::ChannelPresenceChanged {
                channel,
                member_id,
                reachability: match reachability {
                    gcoms_node::node::Reachability::RecentlyReachable => {
                        Reachability::RecentlyReachable
                    }
                    gcoms_node::node::Reachability::Away => Reachability::Away,
                    gcoms_node::node::Reachability::Unknown => Reachability::Unknown,
                },
            },
            Ev::ChannelMessage {
                channel,
                msg_id,
                ts_unix,
                sender,
                channel_epoch,
                sender_index,
                text,
                latency_hint_ms,
            } => Self::ChannelMessage {
                channel,
                message_id: MessageId(msg_id),
                timestamp_unix: ts_unix,
                sender,
                channel_epoch,
                sender_index,
                body: text,
                latency_hint_ms,
            },
            Ev::ChannelDelivery { channel, msg_id } => Self::ChannelDelivered {
                channel,
                message_id: MessageId(msg_id),
            },
            Ev::ChannelRemoved { channel } => Self::ChannelRemoved { channel },
            Ev::ChannelRosterChanged {
                channel,
                channel_id,
            } => Self::ChannelRosterChanged {
                channel,
                channel_id: ChannelId(channel_id.0),
            },
            Ev::ChannelDirectMessage {
                channel,
                sender_member_id,
                recipient_member_id,
                msg_id,
                ts_unix,
                text,
            } => Self::ChannelDirectMessage {
                channel,
                sender_member_id,
                recipient_member_id,
                message_id: MessageId(msg_id),
                timestamp_unix: ts_unix,
                body: text,
            },
            Ev::ChannelDirectDelivery {
                channel,
                recipient_member_id,
                msg_id,
            } => Self::ChannelDirectDelivered {
                channel,
                recipient_member_id,
                message_id: MessageId(msg_id),
            },
            Ev::Lagged { skipped } => Self::EventsLagged { skipped },
        }
    }
}
