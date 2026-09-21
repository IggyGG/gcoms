use gcoms::{sdk, Application};
use serde::Deserialize;
use serde_json::{json, Value};
use zeroize::Zeroize;

/// Secrets are supplied again on resume by the platform unlock provider.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Open {
    #[cfg(feature = "push-gateway")]
    push_gateway: Option<gcoms::runtime::push_notifications::GatewayConfig>,
    application: String,
    profile: String,
    secret: String,
    network: Option<Value>,
    invitation: Option<String>,
    relay: Option<sdk::RelayCard>,
    #[serde(default)]
    peers: Vec<Peer>,
    #[serde(default)]
    fixture: bool,
}
impl Drop for Open {
    fn drop(&mut self) {
        self.secret.zeroize();
        if let Some(invitation) = &mut self.invitation {
            invitation.zeroize();
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    identity: Vec<u8>,
    contact: sdk::ContactCard,
    component: Option<[u8; 16]>,
}
impl From<Peer> for sdk::Peer {
    fn from(p: Peer) -> Self {
        Self {
            identity: p.identity,
            contact: p.contact,
            component: p.component,
        }
    }
}
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    #[cfg(feature = "push")]
    RequestPushRegistration {
        #[serde(default)]
        revoke: bool,
        app_id: String,
        installation_nonce: [u8; 32],
        platform: gcoms::runtime::push_notifications::PushPlatform,
        token: String,
        revision: u64,
        #[serde(default)]
        visible: bool,
    },
    #[cfg(feature = "push")]
    BindPush {
        reference: [u8; 32],
        revision: u64,
        expires: u64,
    },
    Open {
        config: Open,
    },
    Suspend,
    Identity,
    Trust {
        peer: Peer,
    },
    Send {
        contact: sdk::ContactCard,
        content_type: String,
        body: Vec<u8>,
    },
    Inbox {
        after: u64,
        limit: u16,
    },
    Acknowledge {
        sequence: u64,
        digest: [u8; 32],
    },
    Events,
    Channels,
    Roster {
        channel: String,
    },
    CreateChannel {
        channel: String,
        display: String,
        capacity: usize,
        visibility: sdk::ChannelVisibility,
    },
    CreateInvitation {
        channel: String,
        lifetime_secs: u64,
    },
    InspectInvitation {
        link: String,
    },
    JoinInvitation {
        link: String,
        display: String,
        timeout_secs: u64,
    },
    SendChannel {
        channel: String,
        body: Vec<u8>,
    },
    Files {
        request: sdk::sharing::Request,
    },
    Status,
}
pub struct State {
    pub app: Option<Application>,
    events: Option<tokio::sync::mpsc::Receiver<sdk::ClientEvent>>,
    // Only authenticated, explicitly trusted peers are visible in the mobile inbox.
    peers: Vec<sdk::Peer>,
}
impl State {
    pub fn new() -> Self {
        Self {
            app: None,
            events: None,
            peers: vec![],
        }
    }
    pub async fn close(&mut self) -> Result<Value, String> {
        self.events = None;
        self.peers.clear();
        if let Some(app) = self.app.take() {
            app.close().await?;
        }
        Ok(Value::Null)
    }
    pub async fn execute(&mut self, command: Command) -> Result<Value, String> {
        if let Command::Open { mut config } = command {
            if self.app.is_some() {
                return Err("suspend the current profile before opening another".into());
            }
            if config.peers.len() > 256 {
                return Err("too many peers".into());
            }
            let mut builder = Application::builder(&config.application)
                .profile(&config.profile)
                .unlock_secret(std::mem::take(&mut config.secret))
                .receive_messages(false);
            #[cfg(feature = "relay")]
            {
                builder = builder.backend(gcoms::Backend::Embedded);
            }
            #[cfg(feature = "client")]
            {
                builder = builder.backend(gcoms::Backend::NetworkClient);
            }
            if config.fixture {
                #[cfg(feature = "fixtures")]
                {
                    builder = builder.local_fixture();
                }
                #[cfg(not(feature = "fixtures"))]
                {
                    return Err("fixture support is excluded from this package".into());
                }
            } else {
                builder = builder.carrier_profile(sdk::CarrierProfile::Gc2);
            }
            if let Some(network) = config.network.take() {
                builder = builder.network_config(serde_json::to_vec(&network).map_err(err)?);
            }
            if let Some(invitation) = config.invitation.take() {
                builder = builder.invitation(invitation);
            }
            builder = builder.relay(config.relay.take());
            let peers: Vec<sdk::Peer> = std::mem::take(&mut config.peers)
                .into_iter()
                .map(Into::into)
                .collect();
            for peer in &peers {
                builder = builder.peer(peer.clone());
            }
            let app = builder.open().await?;
            #[cfg(feature = "push-gateway")]
            if let Some(gateway) = config.push_gateway.take() {
                if let Err(error) = app
                    .embedded_runtime()
                    .ok_or("runtime unavailable")?
                    .sdk_client()
                    .embedded()
                    .node()
                    .configure_push_gateway(gateway)
                    .await
                {
                    let _ = app.close().await;
                    return Err(error);
                }
            }
            self.events = Some(app.messaging().subscribe_events());
            self.peers = peers;
            let identity = value(app.identity())?;
            self.app = Some(app);
            return Ok(identity);
        }
        if matches!(command, Command::Suspend) {
            return self.close().await;
        }
        let app = self.app.as_ref().ok_or("profile is suspended")?;
        let client = app.messaging();
        match command {
            #[cfg(feature = "push")]
            Command::RequestPushRegistration {
                revoke,
                app_id,
                installation_nonce,
                platform,
                token,
                revision,
                visible,
            } => {
                let request = gcoms::runtime::push_notifications::PushRegistrationRequest {
                    app_id,
                    installation_nonce,
                    platform,
                    token,
                    revision,
                    visible,
                };
                let embedded = app
                    .embedded_runtime()
                    .ok_or("runtime unavailable")?
                    .sdk_client()
                    .embedded();
                let node = embedded.node();
                let ticket = if revoke {
                    node.request_push_revocation(request).await?
                } else {
                    node.request_push_registration(request).await?
                };
                value(ticket)
            }
            #[cfg(feature = "push")]
            Command::BindPush {
                reference,
                revision,
                expires,
            } => {
                app.embedded_runtime()
                    .ok_or("runtime unavailable")?
                    .sdk_client()
                    .embedded()
                    .node()
                    .bind_push_notifications(reference, revision, expires)
                    .await?;
                Ok(Value::Null)
            }
            Command::Open { .. } | Command::Suspend => unreachable!(),
            Command::Identity => value(app.identity()),
            Command::Trust { peer } => {
                let peer: sdk::Peer = peer.into();
                let exists = self
                    .peers
                    .iter()
                    .any(|p| p.identity == peer.identity && p.component == peer.component);
                if !exists && self.peers.len() >= 256 {
                    return Err("too many peers".into());
                }
                app.trust_peer(peer.clone()).await.map_err(err)?;
                if !exists {
                    self.peers.push(peer);
                }
                Ok(Value::Null)
            }
            Command::Send {
                contact,
                content_type,
                body,
            } => value(
                client
                    .submit_durable_opaque(&contact, &content_type, &body)
                    .await
                    .map_err(err)?,
            ),
            Command::Inbox { after, limit } => {
                if !(1..=32).contains(&limit) {
                    return Err("inbox limit must be 1–32".into());
                }
                let deliveries = client.application_inbox(after, limit).await.map_err(err)?;
                let next = deliveries.last().map_or(after, |d| d.sequence);
                let deliveries: Vec<_> = deliveries
                    .into_iter()
                    .filter(|d| {
                        d.destination_component.is_none()
                            && self.peers.iter().any(|p| {
                                p.identity == d.peer_identity && p.component == d.source_component
                            })
                    })
                    .collect();
                Ok(json!({"deliveries": deliveries, "next": next}))
            }
            Command::Acknowledge { sequence, digest } => value(
                client
                    .commit_application(sequence, digest)
                    .await
                    .map_err(err)?,
            ),
            Command::Events => {
                let events = self.events.as_mut().ok_or("missing event subscription")?;
                let mut batch = Vec::new();
                for _ in 0..32 {
                    match events.try_recv() {
                        Ok(event) => batch.push(event),
                        Err(_) => break,
                    }
                }
                value(batch)
            }
            Command::Channels => value(client.list_channels().await.map_err(err)?),
            Command::Roster { channel } => {
                value(client.channel_roster(&channel).await.map_err(err)?)
            }
            Command::CreateChannel {
                channel,
                display,
                capacity,
                visibility,
            } => value(
                client
                    .create_channel(&channel, &display, capacity, visibility)
                    .await
                    .map_err(err)?,
            ),
            Command::CreateInvitation {
                channel,
                lifetime_secs,
            } => value(
                client
                    .create_channel_invitation(&channel, lifetime_secs)
                    .await
                    .map_err(err)?,
            ),
            Command::InspectInvitation { link } => value(
                client
                    .inspect_channel_invitation(&link)
                    .await
                    .map_err(err)?,
            ),
            Command::JoinInvitation {
                link,
                display,
                timeout_secs,
            } => {
                if !(1..=60).contains(&timeout_secs) {
                    return Err("join deadline must be 1–60 seconds".into());
                }
                value(
                    client
                        .join_channel_invitation(&link, &display, timeout_secs)
                        .await
                        .map_err(err)?,
                )
            }
            Command::SendChannel { channel, body } => {
                value(client.send_channel(&channel, &body).await.map_err(err)?)
            }
            Command::Files { request } => value(app.files().request(request).await.map_err(err)?),
            Command::Status => value(client.runtime_status().await.map_err(err)?),
        }
    }
}
fn value(input: impl serde::Serialize) -> Result<Value, String> {
    serde_json::to_value(input).map_err(err)
}
fn err(input: impl std::fmt::Display) -> String {
    input.to_string()
}
