use gcoms_transport::server::{CellHandler, StreamHandler, Tp1Server};
use gcoms_transport::{TokenRegistry, Tp1Client};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn spawn_decoy_server() -> (SocketAddr, [u8; 32]) {
    let registry = TokenRegistry::new();
    let on_cell: CellHandler = Arc::new(|_t: &str, _c: gcoms_core::Cell| Ok(None));
    let on_stream: StreamHandler = Arc::new(|_b: &[u8]| None);
    let identity = gcoms_transport::tls::TlsIdentity::generate().unwrap();
    let server = Tp1Server::bind_with_identity(
        "127.0.0.1:0".parse().unwrap(),
        registry,
        on_cell,
        on_stream,
        &identity,
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();
    let service_id = server.service_id();
    tokio::spawn(server.run());
    (addr, service_id)
}

async fn spawn_tee(target: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    let log_c2s = log.clone();
    tokio::spawn(async move {
        let (client, _) = listener.accept().await.unwrap();
        let upstream = TcpStream::connect(target).await.unwrap();
        let (mut cr, mut cw) = client.into_split();
        let (mut sr, mut sw) = upstream.into_split();
        let c2s = tokio::spawn(async move {
            let mut buf = [0u8; 16384];
            loop {
                let n = match cr.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                log_c2s.lock().unwrap().extend_from_slice(&buf[..n]);
                if sw.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
        let s2c = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut sr, &mut cw).await;
        });
        let _ = tokio::join!(c2s, s2c);
    });
    (proxy_addr, log)
}

struct Ext {
    typ: u16,
    data: Vec<u8>,
}

fn clienthello_extensions(c2s: &[u8]) -> Vec<Ext> {
    assert_eq!(c2s[0], 0x16, "first record is a handshake");
    let rec_len = u16::from_be_bytes([c2s[3], c2s[4]]) as usize;
    let body = &c2s[5..5 + rec_len];
    assert_eq!(body[0], 0x01, "ClientHello");
    let mut p = 4;
    p += 2;
    p += 32;
    let sid_len = body[p] as usize;
    p += 1 + sid_len;
    let cs_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2 + cs_len;
    let comp_len = body[p] as usize;
    p += 1 + comp_len;
    let ext_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let end = p + ext_len;
    let mut out = Vec::new();
    while p + 4 <= end && p + 4 <= body.len() {
        let typ = u16::from_be_bytes([body[p], body[p + 1]]);
        let l = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        out.push(Ext {
            typ,
            data: body[p + 4..p + 4 + l].to_vec(),
        });
        p += 4 + l;
    }
    out
}

fn find_ext(exts: &[Ext], typ: u16) -> Option<&Ext> {
    exts.iter().find(|e| e.typ == typ)
}

#[tokio::test]
async fn clienthello_is_tls13_h2_hybrid_no_sni() {
    let (server_addr, service_id) = spawn_decoy_server().await;
    let (proxy_addr, log) = spawn_tee(server_addr).await;

    let client = Tp1Client::new().unwrap();
    let (status, _) = client
        .get_pinned(proxy_addr, service_id, "/")
        .await
        .unwrap();
    assert_eq!(status, 200);

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let c2s = log.lock().unwrap().clone();
    assert!(c2s.len() > 5, "captured client-to-server bytes");

    let exts = clienthello_extensions(&c2s);

    let sni = find_ext(&exts, 0x0000);
    assert!(sni.is_none(), "ClientHello MUST NOT carry SNI");

    let groups = find_ext(&exts, 0x000A).expect("supported_groups present");
    let list_len = u16::from_be_bytes([groups.data[0], groups.data[1]]) as usize;
    let groups_list: Vec<u16> = groups.data[2..2 + list_len]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    assert_eq!(groups_list, vec![4588], "only X25519MLKEM768 offered");

    let alpn = find_ext(&exts, 0x0010).expect("ALPN present");
    assert!(alpn.data.windows(2).any(|w| w == b"h2"));

    let versions = find_ext(&exts, 0x002B).expect("supported_versions present");
    assert!(versions.data.windows(2).any(|w| w == [0x03, 0x04]));

    let token_like = c2s
        .windows(8)
        .any(|w| w == b"gc-core" || w == b"ghostco" || w == b"gc/1");
    assert!(
        !token_like,
        "no protocol-attributable marker bytes in the clear"
    );
}
