//! One durable hosted owner, with local mutations ahead of network waits.
use super::{api, HostedChannels};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::{Mutex, Notify};

struct Published {
    channels: Vec<api::Channel>,
    files: BTreeMap<[u8; 32], Vec<api::Event>>,
    presence_deadlines: BTreeMap<api::ChannelId, BTreeMap<api::MemberId, u64>>,
}
#[derive(Default)]
pub(crate) struct Owner {
    slot: Mutex<Option<HostedChannels>>,
    views: std::sync::RwLock<Option<Published>>,
    urgent: AtomicUsize,
    wake: Notify,
    closed: AtomicBool,
}
struct Waiting<'a>(&'a AtomicUsize);
impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
fn is_urgent(request: &api::Request) -> bool {
    matches!(
        request,
        api::Request::Create { .. }
            | api::Request::Send { .. }
            | api::Request::SendIdentified { .. }
            | api::Request::Change { .. }
            | api::Request::Invite { .. }
            | api::Request::RotateCode { .. }
            | api::Request::ClearCode { .. }
            | api::Request::SetPresence { .. }
            | api::Request::CommitEvents { .. }
            | api::Request::CommitFileEvents { .. }
    )
}
fn uses_network(request: &api::Request) -> bool {
    matches!(
        request,
        api::Request::Join { .. }
            | api::Request::Sync { .. }
            | api::Request::PutBlob { .. }
            | api::Request::GetBlob { .. }
            | api::Request::Directory { .. }
    )
}
impl Owner {
    fn cache_views(&self, owner: &HostedChannels, failed: bool) {
        *self.views.write().unwrap_or_else(|e| e.into_inner()) =
            if failed || self.closed.load(Ordering::Acquire) {
                None
            } else {
                owner
                    .channels
                    .iter()
                    .map(|(id, client)| client.file_events(16).map(|events| (*id, events)))
                    .collect::<Result<_, _>>()
                    .ok()
                    .map(|files| Published {
                        channels: owner.channels.values().map(super::Client::view).collect(),
                        files,
                        presence_deadlines: owner
                            .channels
                            .iter()
                            .map(|(id, client)| (*id, client.presence_deadlines()))
                            .collect(),
                    })
            };
    }
    pub async fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.views.write().unwrap_or_else(|e| e.into_inner()).take();
        self.wake.notify_waiters();
        self.slot.lock().await.take();
    }
    pub async fn request(
        &self,
        request: api::Request,
        initialize: impl FnOnce() -> Result<HostedChannels, String>,
    ) -> Result<api::Reply, String> {
        // File authority refreshes and UI listings need the latest published
        // durable view, not ownership of an in-flight network transaction.
        // This does not interrupt I/O or relax the live checks on mutations.
        if self.closed.load(Ordering::Acquire) {
            return Err("Hosted owner is closed".into());
        }
        {
            let published = self.views.read().unwrap_or_else(|e| e.into_inner());
            if let Some(view) = published.as_ref() {
                match &request {
                    api::Request::List => {
                        let mut channels = view.channels.clone();
                        let now = super::public::now();
                        for channel in &mut channels {
                            for member in &mut channel.members {
                                let expiry = view
                                    .presence_deadlines
                                    .get(&channel.id)
                                    .and_then(|leases| leases.get(&member.id))
                                    .copied();
                                expire_presence(member, expiry, now);
                            }
                        }
                        return Ok(api::Reply::Channels(channels));
                    }
                    api::Request::FileEvents { channel, limit } if (1..=16).contains(limit) => {
                        if let Some(events) = view.files.get(channel) {
                            return Ok(api::Reply::FileEvents(
                                events.iter().take(usize::from(*limit)).cloned().collect(),
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }
        let priority = is_urgent(&request);
        let mut waiting = priority.then(|| {
            self.urgent.fetch_add(1, Ordering::AcqRel);
            Waiting(&self.urgent)
        });
        if priority {
            self.wake.notify_waiters();
        }
        let network = uses_network(&request);
        let mut initialize = Some(initialize);
        loop {
            // Register before taking the owner lock so a queued network request
            // cannot miss a local mutation's interruption.
            let wake = self.wake.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            let mut slot = self.slot.lock().await;
            if self.closed.load(Ordering::Acquire) {
                return Err("Hosted owner is closed".into());
            }
            if network && self.urgent.load(Ordering::Acquire) != 0 {
                drop(slot);
                tokio::task::yield_now().await;
                continue;
            }
            drop(waiting.take());
            if slot.is_none() {
                *slot = Some(initialize
                    .take()
                    .ok_or("Hosted owner initialization lost")?(
                )?);
            }
            let owner = slot.as_mut().ok_or("Hosted owner is unavailable")?;
            if !network {
                let result = owner.request(request).await;
                self.cache_views(owner, result.is_err());
                return result;
            }
            // Every network await in the client is between durable boundaries:
            // pending appends retain exact bytes, accepted records are fsynced,
            // blob writes are immutable, and admission preparation is read-only
            // until its local queued commit is stored. Cancellation can therefore
            // retry without inventing acceptance or recipient delivery.
            let result = tokio::select! {
                biased;
                _ = &mut wake => None,
                result = owner.request(request.clone()) => Some(result),
            };
            self.cache_views(owner, result.as_ref().is_some_and(Result::is_err));
            if let Some(result) = result {
                return result;
            }
            drop(slot);
            tokio::task::yield_now().await;
        }
    }
}

// A durable view may outlive a signed presence lease while a poll is stalled.
// Expiration remains a local clock check and never extends the remote lease.
fn expire_presence(member: &mut api::Member, expiry: Option<u64>, now: u64) {
    if expiry.is_none_or(|expiry| expiry <= now) {
        member.presence = api::Presence::Unknown;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_presence_expires_at_the_signed_deadline_without_a_network_refresh() {
        for presence in [
            api::Presence::Available,
            api::Presence::Away {
                reason: "busy".into(),
            },
            api::Presence::Invisible,
        ] {
            let member = api::Member {
                id: [1; 32],
                nickname: "peer".into(),
                role: api::Role::Member,
                operator: false,
                voice: false,
                presence: presence.clone(),
            };
            let mut before = member.clone();
            expire_presence(&mut before, Some(100), 99);
            assert_eq!(before.presence, presence);
            for deadline in [Some(100), Some(99), None] {
                let mut expired = member.clone();
                expire_presence(&mut expired, deadline, 100);
                assert_eq!(expired.presence, api::Presence::Unknown);
            }
        }
    }
}
