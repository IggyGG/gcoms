//! A renewed guard alone cannot supply the five independent relays of an
//! application route. Exercise authenticated discovery when referrals arrive
//! after the first successful guard refresh, as at an hourly epoch boundary.
use super::*;
use crate::gc2::directory::BootstrapBundle;
use bytes::Bytes;
use gcoms_core::{gc2::NaturalCell, CellType};
use gcoms_transport::{
    server::{Dispatch, Tp1Server},
    tls::TlsIdentity,
    TokenRegistry,
};
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test]
async fn renewed_guard_retries_incomplete_referrals_before_normal_discovery_period() {
    let identity = TlsIdentity::generate().unwrap();
    let server = Tp1Server::bind_with_identity(
        "127.0.0.121:0".parse().unwrap(),
        TokenRegistry::new(),
        Arc::new(|_, _| Ok(None)),
        Arc::new(|_| None),
        &identity,
    )
    .await
    .unwrap();
    let seed = Introduction {
        addr: server.local_addr().unwrap(),
        service_id: identity.service_id(),
        reentry_cap: [71; 32],
        entry_cap: [72; 32],
        transit_cap: [73; 32],
        expires_at: now_unix() + 600,
    };
    let directory = Arc::new(Directory::for_loopback_fixture());
    directory
        .remember(
            &BootstrapBundle {
                relays: vec![seed.clone()],
            },
            now_unix(),
        )
        .unwrap();
    let reply = Arc::new(RwLock::new(vec![seed.clone()]));
    let requests = Arc::new(AtomicUsize::new(0));
    let response_relays = reply.clone();
    let observed = requests.clone();
    let token = gcoms_transport::encode_b64url(&seed.reentry_cap);
    let handler: gcoms_transport::server::DispatchHandler = Arc::new(move |path, _| {
        if path != token {
            return Dispatch::Rejected;
        }
        let relays = response_relays.read().unwrap().clone();
        let observed = observed.clone();
        Dispatch::Accepted(Box::new(move |mut body, mut response| {
            Box::pin(async move {
                let request = gcoms_transport::server::read_body(&mut body, 32)
                    .await
                    .unwrap();
                let request = NaturalCell::decode(&request).unwrap();
                assert_eq!(request.payload(), discovery::REQUEST);
                let bytes = BootstrapBundle { relays }.encode().unwrap();
                let cell = NaturalCell::new(CellType::Pex, 0, bytes.to_vec()).unwrap();
                let mut send = response
                    .send_response(http::Response::builder().body(()).unwrap(), false)
                    .unwrap();
                send.send_data(Bytes::from(cell.encode()), true).unwrap();
                observed.fetch_add(1, Ordering::SeqCst);
            })
        }))
    });
    let server = tokio::spawn(
        server
            .with_dispatch_factory(Arc::new(move || handler.clone()))
            .run(),
    );
    let (owner, _) =
        EntryOwner::new(directory.clone(), CandidateProfile::file_transfer(), 1).unwrap();
    let owner = tokio::spawn(async move { owner.discovery_loop().await });
    let started = Instant::now();
    timeout(Duration::from_secs(10), async {
        while requests.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("initial authenticated guard refresh");
    let original_guards = directory.guards();
    assert_eq!(original_guards, vec![seed.service_id]);
    // Independently authenticated provider referrals become available only
    // after the first reply. No application request or manual owner wake occurs.
    for id in 122..=125u8 {
        reply.write().unwrap().push(Introduction {
            addr: format!("127.0.0.{id}:4433").parse().unwrap(),
            service_id: [id; 32],
            reentry_cap: [id.wrapping_add(1); 32],
            entry_cap: [id.wrapping_add(2); 32],
            transit_cap: [id.wrapping_add(3); 32],
            expires_at: seed.expires_at,
        });
    }
    let recovered = timeout(Duration::from_secs(75), async {
        loop {
            if directory.eligible(&[], now_unix()).unwrap().len() == 5 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    owner.abort();
    let _ = owner.await;
    server.abort();
    let _ = server.await;
    assert!(
        recovered.is_ok(),
        "fresh guard deferred missing route referrals for the normal five-minute period"
    );
    assert!(
        started.elapsed() >= Duration::from_secs(60),
        "incomplete referrals must retain bounded retry pacing"
    );
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    assert_eq!(
        directory.guards(),
        original_guards,
        "refresh does not replace guards"
    );
    let relays = directory.eligible(&[], now_unix()).unwrap();
    let terminal = relays
        .iter()
        .find(|r| r.service_id != seed.service_id)
        .unwrap();
    let candidates = relays
        .iter()
        .filter(|r| !r.conflicts(terminal.addr, terminal.service_id))
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        super::super::path::select(&candidates, (seed.addr, seed.service_id), now_unix())
            .unwrap()
            .is_some()
    );
}
