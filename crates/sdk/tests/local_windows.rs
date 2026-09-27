#![cfg(windows)]

use gcoms_sdk::local::{connect, LocalListener};
use gcoms_sdk::LocalEndpoint;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn endpoint() -> LocalEndpoint {
    LocalEndpoint::new(format!(
        r"C:\gc-preface-{}-{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

#[tokio::test]
async fn silent_probe_is_not_admitted_and_cancellation_keeps_listener_usable() {
    let endpoint = endpoint();
    let mut listener = LocalListener::bind(&endpoint).unwrap();
    let probe = connect(&endpoint).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "silent connection must not be admitted or terminate the listener"
    );
    drop(probe);
    let server = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        let mut empty = [];
        assert_eq!(stream.read(&mut empty).await.unwrap(), 0);
        let mut frame = vec![0; 262_144];
        stream.read_exact(&mut frame).await.unwrap();
        assert!(frame.iter().enumerate().all(|(i, byte)| *byte == i as u8));
        stream.write_all(b"authenticated").await.unwrap();
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut client = connect(&endpoint).await.unwrap();
        let frame: Vec<u8> = (0..262_144).map(|i| i as u8).collect();
        client.write_all(&frame).await.unwrap();
        let mut reply = [0; 13];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"authenticated");
        server.await.unwrap();
    })
    .await
    .expect("subsequent authenticated framed exchange");
}

#[tokio::test]
async fn disconnected_probe_does_not_terminate_the_listener() {
    let endpoint = endpoint();
    let mut listener = LocalListener::bind(&endpoint).unwrap();
    let server = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        let mut byte = [0];
        stream.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [91]);
        stream.write_all(&[92]).await.unwrap();
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        drop(connect(&endpoint).await.unwrap());
        let mut client = connect(&endpoint).await.unwrap();
        client.write_all(&[91]).await.unwrap();
        let mut reply = [0];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [92]);
        server.await.unwrap();
    })
    .await
    .expect("disconnected peer must not kill acceptance");
}

#[tokio::test]
async fn silent_peer_expires_without_changing_the_next_frame() {
    let endpoint = endpoint();
    let mut listener = LocalListener::bind(&endpoint).unwrap();
    let silent = connect(&endpoint).await.unwrap();
    let server = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        let mut byte = [0];
        stream.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [37]);
        stream.write_all(&[38]).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(2200)).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut client = connect(&endpoint).await.unwrap();
        client.write_all(&[37]).await.unwrap();
        let mut reply = [0];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [38]);
        server.await.unwrap();
    })
    .await
    .expect("silent peer timeout must release admission");
    drop(silent);
}
