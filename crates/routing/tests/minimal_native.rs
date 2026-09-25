#![cfg(feature = "experimental-gc2")]

use gcoms_routing::{
    gc2::directory::BootstrapBundle, route::now_unix, Directory, RelayService, ServicePolicy,
};
use gcoms_transport::{
    duplex::H2Stream,
    server::{DuplexHandler, Tp1Server},
    tls::TlsIdentity,
    TokenRegistry,
};
use std::{
    future::poll_fn,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
    task::JoinSet,
};

#[derive(Default)]
struct Counts {
    entry: AtomicUsize,
    transit: AtomicUsize,
    terminal: AtomicUsize,
    requests: AtomicUsize,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires DS_MINIMAL_TLS_PROBE built with bootstrap qualification"]
async fn native_five_hop_carrier_reuses_routes_and_renews_both_subscriptions() {
    let probe =
        std::env::var_os("DS_MINIMAL_TLS_PROBE").expect("exact native qualification artifact");
    let counts = Arc::new(Counts::default());
    let mut tasks = JoinSet::new();
    let mut stops = Vec::new();
    let mut introductions = Vec::new();
    for index in 0..8 {
        let identity = TlsIdentity::generate().unwrap();
        let server = Tp1Server::bind_with_identity(
            format!("127.0.0.{}:0", 101 + index).parse().unwrap(),
            TokenRegistry::new(),
            Arc::new(|_, _| Ok(None)),
            Arc::new(|_| None),
            &identity,
        )
        .await
        .unwrap();
        let service = RelayService::new(
            server.local_addr().unwrap(),
            identity.service_id(),
            [index + 1; 32],
            Arc::new(Directory::new()),
            ServicePolicy {
                target_allowed: Arc::new(|addr| addr.ip().is_loopback()),
                ..Default::default()
            },
        )
        .unwrap();
        introductions.push(service.gc2_introduction(now_unix()));
        let observed = counts.clone();
        let terminal: DuplexHandler = Arc::new(move |path| {
            if path != "gc2/terminal" {
                return None;
            }
            let observed = observed.clone();
            Some(Box::new(move |body, mut respond| {
                Box::pin(async move {
                    let response = http::Response::builder()
                        .header("content-type", "application/octet-stream")
                        .body(())
                        .unwrap();
                    let send = respond.send_response(response, false).unwrap();
                    let mut io = H2Stream::new(body, send);
                    let mut request = [0u8; 64];
                    io.read_exact(&mut request).await.unwrap();
                    assert_eq!(&request[..6], &[0x20, 0, 0, 0, 0, 58]);
                    assert_eq!(io.read(&mut [0u8; 1]).await.unwrap(), 0);
                    observed.requests.fetch_add(1, Ordering::SeqCst);
                    if request[6] == b'S' && request[7] == 1 {
                        let start: u32 = if request[8] == 0 { 0 } else { 1280 };
                        let mut packet: Vec<u8> = (0..8192).map(|i| i as u8).collect();
                        packet[..6].copy_from_slice(&[0x20, 0, 0, 0, 0x1f, 0xfa]);
                        for sequence in start..1600 {
                            packet[6..10].copy_from_slice(&sequence.to_be_bytes());
                            // Cancellation at 80% deliberately races queued body bytes.
                            if io.write_all(&packet).await.is_err() {
                                return;
                            }
                        }
                    } else {
                        io.write_all(&request).await.unwrap();
                    }
                    if request[6] == b'S' {
                        let _ = poll_fn(|cx| io.poll_reset(cx)).await;
                    } else {
                        io.shutdown().await.unwrap();
                    }
                })
            }))
        });
        let factory = service.gc2_handler_factory_with_terminal(terminal);
        let observed = counts.clone();
        let server = server.with_dispatch_factory(Arc::new(move || {
            let handler = factory();
            let classified = AtomicBool::new(false);
            let observed = observed.clone();
            let intro = service.gc2_introduction(now_unix());
            Arc::new(move |path, registered| {
                if !classified.swap(true, Ordering::SeqCst) {
                    let capability = gcoms_transport::decode_b64url(path).unwrap_or_default();
                    if capability.as_slice() == intro.entry_cap {
                        observed.entry.fetch_add(1, Ordering::SeqCst);
                    } else if capability.as_slice() == intro.transit_cap {
                        observed.transit.fetch_add(1, Ordering::SeqCst);
                    } else if path == "gc2/terminal" {
                        observed.terminal.fetch_add(1, Ordering::SeqCst);
                    }
                }
                handler(path, registered)
            })
        }));
        let (tx, rx) = oneshot::channel();
        stops.push(tx);
        tasks.spawn(async move {
            server
                .run_until(async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });
    }
    let bundle = BootstrapBundle {
        relays: introductions,
    }
    .encode()
    .unwrap();
    let hex: String = bundle.iter().map(|byte| format!("{byte:02x}")).collect();
    let status = tokio::task::spawn_blocking(move || {
        let mut child = std::process::Command::new(probe)
            .args(["--gc2-carrier-probe", &hex])
            .stdin(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let until = Instant::now() + Duration::from_secs(190);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= until {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("native carrier exceeded bounded test duration");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    })
    .await
    .unwrap();
    let actual = [
        counts.entry.load(Ordering::SeqCst),
        counts.transit.load(Ordering::SeqCst),
        counts.terminal.load(Ordering::SeqCst),
        counts.requests.load(Ordering::SeqCst),
    ];
    for stop in stops {
        let _ = stop.send(());
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    assert!(
        status.success(),
        "native exit {status}; [entry, transit, terminal, requests]={actual:?}"
    );
    assert_eq!(
        actual,
        [2, 12, 4, 24],
        "entries and all four complete routes must be retained across requests and renewal"
    );
}
