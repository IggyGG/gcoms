//! Authenticated natural forwarding, composed under the terminal role gate.
use super::*;
use gcoms_core::gc2::{NaturalCell, MAX_CELL};
use gcoms_core::TrafficClass;
use gcoms_protocol::relay::gc2::Forward;
use gcoms_transport::{
    gc2::status_cell,
    server::{AcceptedDuplex, DuplexHandler},
    HopReply,
};

pub(crate) fn handler(
    authorities: Arc<Mutex<ProvisionAuthorities>>,
    scheduler: RelayScheduler,
    service: [u8; 32],
    policy: FrwdTargetPolicy,
) -> DuplexHandler {
    let slots = Arc::new(tokio::sync::Semaphore::new(4));
    let bulk_slots = Arc::new(tokio::sync::Semaphore::new(3));
    Arc::new(move |path| {
        let token = path.strip_prefix("gc2/")?.to_owned();
        authorities
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .lookup_frwd(&token, now_unix())?;
        let authorities = authorities.clone();
        let scheduler = scheduler.clone();
        let policy = policy.clone();
        let bulk_slots = bulk_slots.clone();
        let permit = slots.clone().try_acquire_owned();
        let accepted: AcceptedDuplex = Box::new(move |mut body, mut respond| {
            Box::pin(async move {
                let _permit = match permit {
                    Ok(permit) => permit,
                    Err(_) => {
                        reply(&mut respond, HopReply::Overloaded);
                        return;
                    }
                };
                let result =
                    async {
                        let bytes = gcoms_transport::server::read_body(&mut body, MAX_CELL)
                            .await
                            .ok()?;
                        let cell = NaturalCell::decode(&bytes).ok()?;
                        let now = now_unix();
                        let key = authorities
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .lookup_frwd(&token, now)?;
                        let forward = Forward::decode(&cell, &key, &service, now, &policy).ok()?;
                        let _bulk_permit = if forward.class == TrafficClass::Bulk {
                            match bulk_slots.try_acquire_owned() {
                                Ok(permit) => Some(permit),
                                Err(_) => return Some(HopReply::Overloaded),
                            }
                        } else {
                            None
                        };
                        {
                            let guard = authorities.lock().unwrap_or_else(|p| p.into_inner());
                            if !guard.permits_gc2_frwd(&token, &key, &forward, now) {
                                return None;
                            }
                            if guard.transit_ready.as_ref().is_some_and(|ready| {
                                !ready.load(std::sync::atomic::Ordering::Acquire)
                            }) {
                                return Some(HopReply::Overloaded);
                            }
                        }
                        if forward.push.is_none() {
                            return Some(HopReply::Accepted);
                        }
                        let receipt = match scheduler.forward_gc2(forward) {
                            Ok(receipt) => receipt,
                            Err(_) => return Some(HopReply::Overloaded),
                        };
                        {
                            let mut guard = authorities.lock().unwrap_or_else(|p| p.into_inner());
                            guard.note_frwd_admitted(&token, &key, now);
                            guard
                                .admitted
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        Some(if receipt.completion().await.accepted().is_ok() {
                            HopReply::Accepted
                        } else {
                            HopReply::Overloaded
                        })
                    }
                    .await;
                if let Some(result) = result {
                    reply(&mut respond, result);
                } else if let Ok(mut send) =
                    respond.send_response(gcoms_transport::decoy::decoy_response(404), false)
                {
                    let _ = send.send_data(gcoms_transport::decoy::decoy_body(404), true);
                }
            })
        });
        Some(accepted)
    })
}

fn reply(respond: &mut h2::server::SendResponse<bytes::Bytes>, result: HopReply) {
    if let Ok(mut send) = respond.send_response(http::Response::new(()), false) {
        let _ = send.send_data(bytes::Bytes::from(status_cell(result).encode()), true);
    }
}
