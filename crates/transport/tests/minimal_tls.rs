//! Cross-check the runtime-free verifier against the standard TP-1 TLS identity.
use gcoms_crypto::tls_pin::{certificate_service_id, verify_server_certificate_verify, PinError};
use gcoms_transport::tls::TlsIdentity;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;

fn identity(serial: u64, key: &rcgen::KeyPair) -> TlsIdentity {
    let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
    params.serial_number = Some(serial.into());
    let cert = params.self_signed(key).unwrap();
    TlsIdentity::from_der(cert.der().to_vec(), key.serialize_der()).unwrap()
}

#[test]
fn same_spki_pin_survives_certificate_renewal_and_proves_handshake_key() {
    let key = rcgen::KeyPair::generate().unwrap();
    let first = identity(1, &key);
    let renewed = identity(2, &key);
    assert_ne!(first.certificate_der(), renewed.certificate_der());
    assert_eq!(
        certificate_service_id(first.certificate_der()).unwrap(),
        first.service_id()
    );
    assert_eq!(
        certificate_service_id(renewed.certificate_der()).unwrap(),
        first.service_id()
    );
    let signing = SigningKey::from_pkcs8_der(&key.serialize_der()).unwrap();
    let hash = [0x42; 32];
    let mut message = vec![0x20; 64];
    message.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    message.extend_from_slice(&hash);
    let signature: Signature = signing.sign(&message);
    let signature = signature.to_der();
    assert_eq!(
        verify_server_certificate_verify(
            first.certificate_der(),
            &first.service_id(),
            0x0403,
            &hash,
            signature.as_bytes()
        ),
        Ok(())
    );
    assert_eq!(
        verify_server_certificate_verify(
            renewed.certificate_der(),
            &first.service_id(),
            0x0403,
            &hash,
            signature.as_bytes()
        ),
        Ok(())
    );
    assert_eq!(
        verify_server_certificate_verify(
            first.certificate_der(),
            &[0; 32],
            0x0403,
            &hash,
            signature.as_bytes()
        ),
        Err(PinError::Pin)
    );
    assert_eq!(
        verify_server_certificate_verify(
            first.certificate_der(),
            &first.service_id(),
            0x0807,
            &hash,
            signature.as_bytes()
        ),
        Err(PinError::Algorithm)
    );
    assert_eq!(
        verify_server_certificate_verify(
            first.certificate_der(),
            &first.service_id(),
            0x0403,
            &[0x43; 32],
            signature.as_bytes()
        ),
        Err(PinError::Signature)
    );
    // The public certificate alone is not sufficient: a different signing key
    // cannot complete a handshake while presenting that certificate.
    let other = SigningKey::from_slice(&[0x45; 32]).unwrap();
    let forged: Signature = other.sign(&message);
    assert_eq!(
        verify_server_certificate_verify(
            first.certificate_der(),
            &first.service_id(),
            0x0403,
            &hash,
            forged.to_der().as_bytes()
        ),
        Err(PinError::Signature)
    );
}

#[test]
fn certificate_and_signature_parsers_reject_truncation_and_extensions() {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = identity(3, &key);
    for length in 0..cert.certificate_der().len() {
        assert!(certificate_service_id(&cert.certificate_der()[..length]).is_err());
    }
    let mut extended = cert.certificate_der().to_vec();
    extended.push(0);
    assert_eq!(
        certificate_service_id(&extended),
        Err(PinError::Certificate)
    );
    assert_eq!(
        certificate_service_id(&vec![0; 8193]),
        Err(PinError::Certificate)
    );
    for signature in [vec![], vec![0; 64], vec![0x30, 0x80, 0, 0]] {
        assert_eq!(
            verify_server_certificate_verify(
                cert.certificate_der(),
                &cert.service_id(),
                0x0403,
                &[1; 32],
                &signature
            ),
            Err(PinError::Signature)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a native DS_MINIMAL_TLS_PROBE executable and the qualification lock"]
async fn native_c_handshake_accepts_only_the_pinned_relay_and_h2() {
    use std::{sync::Arc, time::Duration};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    let probe = std::env::var_os("DS_MINIMAL_TLS_PROBE")
        .expect("set DS_MINIMAL_TLS_PROBE to the exact native artifact");
    // Retain the original 384 handshakes and add 12 with record fragmentation.
    // This exercises ServerHello and encrypted flights, not just TCP chunking.
    for round in 0usize..132 {
        let fragment = [32, 64, 256, 1024].get(round.wrapping_sub(128)).copied();
        let identity = TlsIdentity::generate().unwrap();
        assert_eq!(
            certificate_service_id(identity.certificate_der()).unwrap(),
            identity.service_id(),
            "round {round}"
        );
        let pin = identity
            .service_id()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        for (case, claimed, alpn, success) in [
            ("matching pin", pin, b"h2".to_vec(), true),
            ("wrong pin", "ab".repeat(32), b"h2".to_vec(), false),
            (
                "missing h2",
                identity
                    .service_id()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
                b"http/1.1".to_vec(),
                false,
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let mut config = identity.server_config().unwrap();
            config.alpn_protocols = vec![alpn];
            config.max_fragment_size = fragment;
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let server = tokio::spawn(async move {
                // A native loader failure can exit before connecting. Bound
                // accept as well as TLS so that failure cannot hang the gate.
                tokio::time::timeout(Duration::from_secs(10), async move {
                    let (stream, _) = listener.accept().await?;
                    acceptor.accept(stream).await
                })
                .await
            });
            let probe = probe.clone();
            let child = tokio::task::spawn_blocking(move || {
                let mut process = std::process::Command::new(probe)
                    .args([
                        "--relay",
                        "127.0.0.1",
                        &address.port().to_string(),
                        &claimed,
                    ])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap();
                let deadline = std::time::Instant::now() + Duration::from_secs(15);
                loop {
                    if let Some(status) = process.try_wait().unwrap() {
                        break status;
                    }
                    if std::time::Instant::now() >= deadline {
                        process.kill().unwrap();
                        process.wait().unwrap();
                        panic!("native probe timed out");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
            let status = child.await.unwrap();
            let server_result = server.await.unwrap();
            if status.success() != success {
                eprintln!("{case}: server result {server_result:?}");
            }
            let accepted = server_result.is_ok_and(|r| r.is_ok());
            assert_eq!(
                status.code(),
                Some(if success { 0 } else { 4 }),
                "{case}, record fragment {fragment:?}: {status}"
            );
            assert_eq!(accepted, success, "{case}: server handshake");
        }
    }
}

async fn run_http2_probe(
    address: std::net::SocketAddr,
    pin: [u8; 32],
    token: &str,
    streaming: bool,
) -> std::process::ExitStatus {
    run_native_probe(vec![
        if streaming {
            "--relay-h2-stream"
        } else {
            "--relay-h2"
        }
        .into(),
        "127.0.0.1".into(),
        address.port().to_string(),
        pin.iter().map(|b| format!("{b:02x}")).collect(),
        token.into(),
    ])
    .await
}

async fn run_native_probe(args: Vec<String>) -> std::process::ExitStatus {
    let probe = std::env::var_os("DS_MINIMAL_TLS_PROBE")
        .expect("set DS_MINIMAL_TLS_PROBE to the exact native artifact");
    tokio::task::spawn_blocking(move || {
        let mut child = std::process::Command::new(probe)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("native transport probe exceeded the test guard");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a native DS_MINIMAL_TLS_PROBE executable and the qualification lock"]
async fn native_c_deadline_bounds_stalled_and_trickling_peers() {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };
    use tokio::{io::AsyncWriteExt, net::TcpListener};
    use tokio_rustls::TlsAcceptor;
    for case in [
        "refused",
        "eof",
        "tls stall",
        "tls trickle",
        "h2 stall",
        "h2 trickle",
    ] {
        let identity = TlsIdentity::generate().unwrap();
        let pin = identity
            .service_id()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let h2 = case.starts_with("h2");
        let acceptor = TlsAcceptor::from(Arc::new(identity.server_config().unwrap()));
        let server = if case == "refused" {
            drop(listener);
            None
        } else {
            Some(tokio::spawn(async move {
                let (mut tcp, _) = listener.accept().await.unwrap();
                if case == "eof" {
                    return;
                }
                if case == "tls stall" {
                    std::future::pending::<()>().await;
                }
                if case == "tls trickle" {
                    // Valid TLS record prefix, deliberately unfinished body.
                    if tcp.write_all(&[22, 3, 3, 0x10, 0]).await.is_err() {
                        return;
                    }
                    loop {
                        if tcp.write_all(&[0]).await.is_err() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(40)).await;
                    }
                }
                let tls = acceptor.accept(tcp).await.unwrap();
                let mut connection = h2::server::handshake(tls).await.unwrap();
                let (_request, mut respond) = connection.accept().await.unwrap().unwrap();
                let response = http::Response::builder()
                    .status(200)
                    .header("content-type", "application/octet-stream")
                    .body(())
                    .unwrap();
                let mut stream = respond.send_response(response, false).unwrap();
                // Keep driving the connection while the response body is open.
                loop {
                    tokio::select! {
                        next = connection.accept() => { if next.is_none() { break; } }
                        _ = tokio::time::sleep(Duration::from_millis(40)) => {
                            if case == "h2 trickle" && stream.send_data(bytes::Bytes::from_static(&[0]), false).is_err() { break; }
                        }
                    }
                }
            }))
        };
        let mut args = vec![
            if h2 { "--relay-h2" } else { "--relay" }.into(),
            "127.0.0.1".into(),
            address.port().to_string(),
            pin,
        ];
        if h2 {
            args.push("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
        }
        args.push("500".into()); // Same production deadline path, shorter diagnostic limit.
        let start = Instant::now();
        let status = run_native_probe(args).await;
        let elapsed = start.elapsed();
        if let Some(server) = server {
            server.abort();
            if let Err(error) = server.await {
                assert!(error.is_cancelled(), "{case}: {error}");
            }
        }
        assert_eq!(status.code(), Some(if h2 { 5 } else { 4 }), "{case}");
        assert!(
            elapsed < Duration::from_secs(3),
            "{case}: client failed its own deadline: {elapsed:?}"
        );
        if case.ends_with("stall") || case.ends_with("trickle") {
            assert!(
                elapsed >= Duration::from_millis(450),
                "{case}: rejected before reaching the deadline: {elapsed:?}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a native DS_MINIMAL_TLS_PROBE executable and the qualification lock"]
async fn native_c_http2_uses_existing_tp1_post_and_stream_paths() {
    use gcoms_core::{decode, Cell, CellType};
    use gcoms_transport::{
        server::{CellHandler, QueueReject, StreamHandler, Tp1Server},
        TokenRegistry,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    // Public, test-only capability. Never use production config in diagnostics.
    const TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    for case in [
        "echo",
        "unknown token",
        "unauthorized",
        "wrong cell",
        "stream",
    ] {
        let registry = TokenRegistry::new();
        if case == "stream" {
            registry.insert_stream(TOKEN);
        } else if case != "unknown token" {
            registry.insert_post(TOKEN);
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let on_cell: CellHandler = Arc::new(move |token, cell| {
            seen.fetch_add(1, Ordering::SeqCst);
            assert_eq!(token, TOKEN);
            assert_eq!(cell, Cell::new(CellType::Ack, 0, 0, vec![0x5a]));
            match case {
                "unauthorized" => Err(QueueReject::Unauthorized),
                "wrong cell" => Ok(Some(Cell::new(CellType::Ack, 0, 0, vec![0x5b]))),
                _ => Ok(Some(cell)),
            }
        });
        let seen = calls.clone();
        let on_stream: StreamHandler = Arc::new(move |body| {
            seen.fetch_add(1, Ordering::SeqCst);
            let cell = Cell::new(CellType::Ack, 0, 0, vec![0x5a]);
            assert_eq!(decode(body).unwrap(), cell);
            Some(Box::new(move |sink| {
                tokio::spawn(async move {
                    for _ in 0..32 {
                        assert!(sink.send(cell.clone()).await);
                    }
                });
            }))
        });
        let identity = TlsIdentity::generate().unwrap();
        let server = Tp1Server::bind_with_identity(
            "127.0.0.1:0".parse().unwrap(),
            registry,
            on_cell,
            on_stream,
            &identity,
        )
        .await
        .unwrap();
        let address = server.local_addr().unwrap();
        let server = tokio::spawn(server.run());
        let status = run_http2_probe(address, identity.service_id(), TOKEN, case == "stream").await;
        server.abort();
        let _ = server.await;
        assert_eq!(
            status.code(),
            Some(if matches!(case, "echo" | "stream") {
                0
            } else {
                5
            }),
            "{case}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            usize::from(case != "unknown token"),
            "{case}"
        );
    }
}
