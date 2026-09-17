use gcoms_transport::server::{CellHandler, StreamHandler, Tp1Server};
use gcoms_transport::{generate_token, TokenRegistry, Tp1Client};
use rand::Rng;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone)]
struct ChunkLog {
    start: Instant,
    file: Arc<std::sync::Mutex<std::fs::File>>,
    counter: Arc<AtomicU64>,
}

impl ChunkLog {
    fn log(&self, data: &[u8]) {
        let mut f = self.file.lock().unwrap();
        let mut hdr = Vec::with_capacity(12);
        let nanos = self.start.elapsed().as_nanos() as u64;
        hdr.extend_from_slice(&nanos.to_be_bytes());
        hdr.extend_from_slice(&(data.len() as u32).to_be_bytes());
        let _ = f.write_all(&hdr);
        let _ = f.write_all(data);
        self.counter.fetch_add(1, Ordering::Relaxed);
    }
}

async fn tee_proxy(target: SocketAddr, out_dir: &str, tag: &str) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let start = Instant::now();
    let c2s = ChunkLog {
        start,
        file: Arc::new(Mutex::new(std::fs::File::create(format!(
            "{out_dir}/{tag}_c2s.chunks"
        ))?)),
        counter: Arc::new(AtomicU64::new(0)),
    };
    let s2c = ChunkLog {
        start,
        file: Arc::new(Mutex::new(std::fs::File::create(format!(
            "{out_dir}/{tag}_s2c.chunks"
        ))?)),
        counter: Arc::new(AtomicU64::new(0)),
    };
    tokio::spawn(async move {
        loop {
            let (client, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            let upstream = match TcpStream::connect(target).await {
                Ok(u) => u,
                Err(_) => continue,
            };
            let (mut cr, mut cw) = client.into_split();
            let (mut sr, mut sw) = upstream.into_split();
            let c2s = c2s.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 16384];
                loop {
                    let n = match cr.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    c2s.log(&buf[..n]);
                    if sw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
            let s2c = s2c.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 16384];
                loop {
                    let n = match sr.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    s2c.log(&buf[..n]);
                    if cw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Ok(addr)
}

async fn gc_flow(out_dir: &str) {
    let registry = TokenRegistry::new();
    let token = generate_token();
    registry.insert_post(&token);
    let on_cell: CellHandler = Arc::new(|_t: &str, c: gcoms_core::Cell| Ok(Some(c)));
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
    let server_addr = server.local_addr().unwrap();
    let service_id = server.service_id();
    tokio::spawn(server.run());

    let proxy_addr = tee_proxy(server_addr, out_dir, "gc").await.unwrap();
    let client = Tp1Client::new().unwrap();
    let mut rng = rand::thread_rng();
    for i in 0..8 {
        let cell = gcoms_core::Cell::new(
            gcoms_core::CellType::Msg,
            0,
            i as u16,
            vec![0x41; 120 + (i * 37) % 300],
        );
        let outcome = client
            .post_cell_pinned(
                proxy_addr,
                service_id,
                &token,
                bytes::Bytes::from(cell.encode_wire().unwrap()),
            )
            .await
            .unwrap();
        assert!(outcome.is_accepted());
        tokio::time::sleep(Duration::from_millis(rng.gen_range(2000..4000))).await;
    }
}

async fn ref_flow(out_dir: &str) {
    let target: SocketAddr = std::net::ToSocketAddrs::to_socket_addrs(&("crates.io", 443u16))
        .unwrap()
        .next()
        .expect("resolve crates.io");
    println!("ref target: {target}");
    let proxy_addr = tee_proxy(target, out_dir, "ref").await.unwrap();
    let port = proxy_addr.port();
    for path in [
        "https://crates.io/",
        "https://crates.io/api/v1/summary",
        "https://crates.io/search?q=tokio",
        "https://crates.io/api/v1/crates?page=1",
        "https://crates.io/api/v1/crates?page=2",
    ] {
        let url = path.to_string();
        let status = std::process::Command::new("curl")
            .args([
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                "15",
                "-A",
                "Mozilla/5.0 (X11; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0",
                "--connect-to",
                &format!("crates.io:443:127.0.0.1:{port}"),
                &url,
            ])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string());
        println!("ref fetch {path} -> {:?}", status);
        tokio::time::sleep(Duration::from_millis(1200)).await;
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let out_dir = std::env::args().nth(2).unwrap_or_else(|| ".".to_string());
    match mode.as_str() {
        "gc" => gc_flow(&out_dir).await,
        "ref" => ref_flow(&out_dir).await,
        _ => {
            eprintln!("usage: gcflow <gc|ref> <outdir>");
            std::process::exit(2);
        }
    }
    println!("gcflow {mode} done -> {out_dir}");
}
