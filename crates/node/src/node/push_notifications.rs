use super::*;
use crate::push_notifications::Binding;

impl NodeHandle {
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
        let host = self
            .notification_host
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .ok_or("relay hosting is unavailable")?;
        let mut tasks = self.tasks.lock().await;
        let tasks = tasks.as_mut().ok_or("node is stopped")?;
        let (sender, events) = tokio::sync::mpsc::channel(256);
        host.leases
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .install_notification_sink(sender)?;
        tasks.push(tokio::spawn(crate::push_notifications::worker(
            config, client, events,
        )));
        Ok(())
    }
}
