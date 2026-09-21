#![cfg(all(unix, feature = "ipc"))]

use gcoms_sdk::local::{connect, LocalListener};
use gcoms_sdk::LocalEndpoint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn disconnected_probe_does_not_stop_listener() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = LocalEndpoint::new(directory.path().join("probe.sock"));
    let mut listener = LocalListener::bind(&endpoint).unwrap();

    // macOS may lose peer credentials as soon as this probe disconnects.
    drop(connect(&endpoint).await.unwrap());
    let mut client = connect(&endpoint).await.unwrap();
    client.write_all(b"ready").await.unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let mut stream = listener.accept().await.unwrap();
            let mut data = [0; 5];
            // Linux can still authenticate the closed probe; skip its EOF.
            if stream.read(&mut data[..1]).await.unwrap() == 0 {
                continue;
            }
            stream.read_exact(&mut data[1..]).await.unwrap();
            assert_eq!(&data, b"ready");
            break;
        }
    })
    .await
    .unwrap();
    endpoint.cleanup().unwrap();
}
