//! Count every owned direct-outbox payload copy, including committed retry
//! ciphertext and logical records. Metadata, encrypted checkpoint scratch and
//! the separately bounded application inbox are not included in this count.
use super::*;
use crate::scheduler::{PayloadUsage, RetainedPriority, RetainedUpdate};

impl DirectDelivery {
    pub(crate) fn retained_payload(&self) -> PayloadUsage {
        PayloadUsage {
            items: self.cells.len(),
            bytes: self.cells.iter().map(|cell| cell.payload.len()).sum(),
        }
    }
}

impl PendingDirect {
    pub(crate) fn retained_payload(&self) -> PayloadUsage {
        let mut usage = self.delivery.retained_payload();
        if let Some(record) = &self.logical_record {
            usage.add(PayloadUsage {
                items: 1,
                bytes: record.len(),
            });
        }
        usage
    }
}

impl NodeState {
    pub(crate) fn retained_payload(
        &self,
        session_override: Option<(&[u8], &peer_session::Snapshot)>,
    ) -> Result<PayloadUsage, String> {
        let mut usage = PayloadUsage::default();
        for (peer, session) in &self.sessions {
            usage.add(
                match session_override.filter(|(key, _)| *key == peer.as_slice()) {
                    Some((_, snapshot)) => snapshot.retained_payload()?,
                    None => session.retained_payload(),
                },
            );
        }
        for pending in self.pending_1to1.values() {
            usage.add(pending.retained_payload());
        }
        for ack in &self.direct_ack_outbox {
            usage.add(ack.retained_payload());
        }
        for processed in self.processed_direct.values() {
            usage.add(processed.delivery.retained_payload());
        }
        Ok(usage)
    }

    pub(crate) fn stage_retained_usage(
        &self,
        usage: PayloadUsage,
        control: bool,
    ) -> Result<Option<RetainedUpdate<'_>>, String> {
        if !self.gc2_sessions {
            return Ok(None);
        }
        self.retained_direct
            .get_or_init(|| self.scheduler.retained_account())
            .stage(
                usage,
                if control {
                    RetainedPriority::Control
                } else {
                    RetainedPriority::Application
                },
            )
            .map(Some)
            .map_err(|e| format!("direct retained payload admission: {e}"))
    }

    pub(crate) fn stage_retained(
        &self,
        session_override: Option<(&[u8], &peer_session::Snapshot)>,
        control: bool,
    ) -> Result<Option<RetainedUpdate<'_>>, String> {
        if !self.gc2_sessions {
            return Ok(None);
        }
        self.stage_retained_usage(self.retained_payload(session_override)?, control)
    }

    /// Removal after expiry or successful dispatch need not write the archive:
    /// a crash may safely retry its old ciphertext. Reclaim the live RAM charge.
    pub(crate) fn release_removed_direct_payload(&self) {
        match self.stage_retained(None, true) {
            Ok(Some(update)) => update.commit(),
            Ok(None) => (),
            Err(error) => metrics::log_event("direct_budget_release_error", &[("e", error)]),
        }
    }
}
