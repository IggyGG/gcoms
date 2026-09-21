use super::*;
use crate::push_notifications::{
    Binding, PushRegistrationRequest, PushRegistrationTicket, TicketRequest,
};

impl NodeHandle {
    /// Obtain a token-bound ticket from an existing owned relay lease. This does
    /// not provision an inbox, dial a carrier, or extend any lease deadline.
    pub async fn request_push_registration(
        &self,
        request: PushRegistrationRequest,
    ) -> Result<PushRegistrationTicket, String> {
        self.request_push_ticket(request, false).await
    }

    /// Revoke by installation identity even if a registration response (and its
    /// rotated management token) was lost. Persist a newer revision first.
    pub async fn request_push_revocation(
        &self,
        request: PushRegistrationRequest,
    ) -> Result<PushRegistrationTicket, String> {
        self.request_push_ticket(request, true).await
    }

    async fn request_push_ticket(
        &self,
        request: PushRegistrationRequest,
        revoke: bool,
    ) -> Result<PushRegistrationTicket, String> {
        let now = now_unix();
        let aliases = {
            let state = self.state.upgrade().ok_or("node is stopped")?;
            let state = state.lock().unwrap_or_else(|p| p.into_inner());
            state
                .client_relay
                .aliases
                .iter()
                .filter(|alias| alias.contact.expiry > now)
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
        };
        if aliases.is_empty() {
            return Err("inbox relay is not ready".into());
        }
        // Failover stays on existing protected administrative routes. Old relays
        // may reject the new opcode without affecting ordinary messaging.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut failure = "push registration unavailable".to_string();
        for alias in aliases {
            let mut wire_request = TicketRequest::new(
                request.clone(),
                &self.info.identity_pk,
                now.saturating_add(300).min(alias.contact.expiry),
                random_nonzero(),
            )?;
            if revoke {
                wire_request.revoke()?;
            }
            let digest = wire_request.digest(
                &alias.contact.queue_id,
                alias.contact.epoch,
                &alias.contact.target.relay_service_id,
            )?;
            wire_request.signature =
                gcoms_transport::encode_b64url(&self.sign_identity_digest(digest).await?);
            let wire = wire_request.encode(
                &alias.contact.queue_id,
                alias.contact.epoch,
                &alias.capabilities.admin,
                &alias.contact.target.relay_service_id,
            )?;
            let receipt = self
                .scheduler
                .admin_post(
                    alias.contact.target.clone(),
                    alias.create_path.clone(),
                    Cell::new(CellType::RelaySub, 0, 0, wire),
                )
                .map_err(|error| error.to_string())?;
            match tokio::time::timeout_at(deadline, receipt.completion())
                .await
                .map_err(|_| "push registration timed out; reconcile before retrying")?
                .accepted()
            {
                Ok(bytes) => {
                    let reply =
                        gcoms_core::decode(&bytes).map_err(|_| "invalid push ticket envelope")?;
                    if reply.cell_type() != Some(CellType::Ack) {
                        return Err("invalid push ticket envelope".into());
                    }
                    let ticket: PushRegistrationTicket = serde_json::from_slice(&reply.payload)
                        .map_err(|_| "invalid push ticket reply")?;
                    let origin = url::Url::parse(&ticket.gateway_origin)
                        .map_err(|_| "invalid push gateway origin")?;
                    if origin.scheme() != "https"
                        || origin.host_str().is_none()
                        || !origin.username().is_empty()
                        || origin.password().is_some()
                        || origin.origin().ascii_serialization() != ticket.gateway_origin
                        || ticket.expires <= now
                        || ticket.expires > wire_request.expires
                        || ticket.installation != wire_request.installation()?
                        || ticket.ticket.len() > 2048
                    {
                        return Err("invalid push registration reply scope".into());
                    }
                    return Ok(ticket);
                }
                Err(error) => failure = error,
            }
        }
        Err(failure)
    }

    /// Bind current owned inboxes to a gateway reference. All-zero reference
    /// removes the binding. The host app durably allocates monotonically
    /// increasing revisions and rebinds current aliases before suspension.
    pub async fn bind_push_notifications(
        &self,
        reference: [u8; 32],
        revision: u64,
        expires: u64,
    ) -> Result<(), String> {
        let now = now_unix();
        if revision == 0 || expires <= now || expires > now.saturating_add(86400) {
            return Err(
                "binding requires a nonzero revision and a lifetime of at most one day".into(),
            );
        }
        let aliases = {
            let state = self.state.upgrade().ok_or("node is stopped")?;
            let state = state.lock().unwrap_or_else(|p| p.into_inner());
            let mut aliases = state.client_relay.aliases.clone();
            for channel in state.channels.values() {
                aliases.extend(channel.own_route.aliases.iter().cloned());
            }
            let mut seen = std::collections::HashSet::new();
            aliases.retain(|alias| {
                seen.insert((
                    alias.contact.target.relay_service_id,
                    alias.contact.queue_id,
                ))
            });
            if aliases.len() > 256 {
                return Err("too many inbox aliases for one notification binding".into());
            }
            aliases
        };
        if aliases.is_empty() {
            return Err("inbox relay is not ready".into());
        }
        if aliases.iter().any(|alias| alias.contact.expiry <= now) {
            return Err("inbox relay lease has expired".into());
        }
        for alias in aliases {
            let binding = Binding {
                queue: alias.contact.queue_id,
                epoch: alias.contact.epoch,
                revision,
                expires: expires.min(alias.contact.expiry),
                nonce: random_nonzero(),
                reference,
            };
            let wire = binding.encode(
                &alias.capabilities.admin,
                &alias.contact.target.relay_service_id,
            )?;
            // Keep the existing protected administrative route and pinned relay.
            let receipt = self
                .scheduler
                .admin_post(
                    alias.contact.target.clone(),
                    alias.create_path.clone(),
                    Cell::new(CellType::RelaySub, 0, 0, wire),
                )
                .map_err(|e| e.to_string())?;
            tokio::time::timeout(std::time::Duration::from_secs(30), receipt.completion())
                .await
                .map_err(|_| "notification binding timed out; reconcile before retrying")?
                .accepted()?;
        }
        Ok(())
    }

    #[cfg(feature = "push-gateway")]
    pub async fn configure_push_gateway(
        &self,
        config: crate::push_notifications::GatewayConfig,
    ) -> Result<(), String> {
        let client = config.client()?;
        let issuer = config.issuer()?;
        let host = self
            .notification_host
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .ok_or("relay hosting is unavailable")?;
        let mut tasks = self.tasks.lock().await;
        let tasks = tasks.as_mut().ok_or("node is stopped")?;
        let (sender, events) = tokio::sync::mpsc::channel(256);
        {
            let mut leases = host.leases.lock().unwrap_or_else(|p| p.into_inner());
            leases.install_notification_sink(sender)?;
            leases.install_ticket_issuer(issuer);
        }
        tasks.push(tokio::spawn(crate::push_notifications::worker(
            config, client, events,
        )));
        Ok(())
    }
}
