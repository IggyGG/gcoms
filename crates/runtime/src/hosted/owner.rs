//! One durable hosted owner, with local mutations ahead of network waits.
use super::{api, HostedChannels};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::{Mutex, Notify};

#[derive(Default)]
pub(crate) struct Owner {
    slot: Mutex<Option<HostedChannels>>,
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
    pub async fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.wake.notify_waiters();
        self.slot.lock().await.take();
    }
    pub async fn request(
        &self,
        request: api::Request,
        initialize: impl FnOnce() -> Result<HostedChannels, String>,
    ) -> Result<api::Reply, String> {
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
                return owner.request(request).await;
            }
            // Every network await in the client is between durable boundaries:
            // pending appends retain exact bytes, accepted records are fsynced,
            // blob writes are immutable, and admission preparation is read-only
            // until its local queued commit is stored. Cancellation can therefore
            // retry without inventing acceptance or recipient delivery.
            tokio::select! {
                biased;
                _ = &mut wake => {},
                result = owner.request(request.clone()) => return result,
            }
            drop(slot);
            tokio::task::yield_now().await;
        }
    }
}
