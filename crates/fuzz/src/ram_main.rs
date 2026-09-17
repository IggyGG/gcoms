use gcoms_core::{Cell, CellType};
use gcoms_crypto::IdentityKeypair;
use gcoms_mls::{Caps, ChannelMember, OwnerSession};
use gcoms_transport::server::{CellHandler, StreamHandler, Tp1Server};
use gcoms_transport::{generate_token, TokenRegistry, Tp1Client};
use std::collections::HashSet;
use std::path::Path;
use std::time::{Duration, Instant};

const VERIFY_ROUNDS: u64 = 25;
const SOAK_DURATION: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, PartialEq)]
enum Mode {
    Verify,
    Soak,
}

fn parse_mode(args: impl IntoIterator<Item = String>) -> Result<Mode, String> {
    let args: Vec<_> = args.into_iter().collect();
    match args.as_slice() {
        [] => Ok(Mode::Verify),
        [arg] if arg == "--soak" => Ok(Mode::Soak),
        _ => Err("usage: gcramcheck [--soak]".to_string()),
    }
}

fn snapshot_files(root: &Path) -> HashSet<std::path::PathBuf> {
    let mut out = HashSet::new();
    fn walk(dir: &Path, out: &mut HashSet<std::path::PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else {
                    out.insert(p);
                }
            }
        }
    }
    walk(root, &mut out);
    out
}

async fn run_round(round: u64) {
    let registry = TokenRegistry::new();
    let post = generate_token();
    let stream = generate_token();
    registry.insert_post(&post);
    registry.insert_stream(&stream);
    let on_cell: CellHandler = std::sync::Arc::new(|_t: &str, c: gcoms_core::Cell| Ok(Some(c)));
    let on_stream: StreamHandler = std::sync::Arc::new(|_b: &[u8]| None);
    let identity = gcoms_transport::tls::TlsIdentity::generate().expect("identity");
    let server = Tp1Server::bind_with_identity(
        "127.0.0.1:0".parse().unwrap(),
        registry,
        on_cell,
        on_stream,
        &identity,
    )
    .await
    .expect("bind");
    let addr = server.local_addr().unwrap();
    let service_id = server.service_id();
    let server_task = tokio::spawn(server.run());

    let client = Tp1Client::new().expect("client");
    let cell = Cell::new(CellType::Msg, 0, round as u16, vec![7; 100]);
    let outcome = client
        .post_cell_pinned(
            addr,
            service_id,
            &post,
            bytes::Bytes::from(cell.encode_wire().unwrap()),
        )
        .await
        .expect("post");
    assert!(outcome.is_accepted());
    let (status, body) = client.get_pinned(addr, service_id, "/").await.expect("get");
    assert_eq!(status, 200);
    assert!(!body.is_empty());
    server_task.abort();
    let _ = server_task.await;

    let bob = IdentityKeypair::from_seed([(round % 250) as u8; 32]);
    let (bundle, secrets) = bob.issue_bundle();
    let (fm, mut alice) =
        gcoms_crypto::initiate(&bob.public_bytes(), &bundle, b"ramcheck").expect("initiate");
    let (p0, mut bob_session) = secrets.accept(&fm).expect("accept");
    assert_eq!(p0, b"ramcheck");
    for i in 0..5 {
        let a = format!("a{i}");
        let f = alice.send(a.as_bytes()).unwrap();
        assert_eq!(bob_session.receive(&f).unwrap(), a.as_bytes());
        let b = format!("b{i}");
        let g = bob_session.send(b.as_bytes()).unwrap();
        assert_eq!(alice.receive(&g).unwrap(), b.as_bytes());
    }

    let mut owner =
        OwnerSession::create(IdentityKeypair::from_seed([0x5A; 32]), "founder", 64).unwrap();
    let prepared = ChannelMember::prepare("member").unwrap();
    let kp_bytes = gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap();
    let invite = owner.sign_invite_key_package(&kp_bytes, "member", Caps::member(), 3600);
    let admission = owner.admit(&invite, &kp_bytes).unwrap();
    let mut member = ChannelMember::join(prepared, &admission.welcome).unwrap();
    let msg = owner.send(b"channel msg").unwrap();
    assert_eq!(member.receive(&msg).unwrap().unwrap().1, b"channel msg");
}

async fn run(mode: Mode) -> bool {
    let watch_dir = std::env::current_dir().expect("cwd");
    let before = snapshot_files(&watch_dir);
    match mode {
        Mode::Verify => println!(
            "ramcheck: short verification, {VERIFY_ROUNDS} full-stack rounds under {} ({} pre-existing files)",
            watch_dir.display(),
            before.len()
        ),
        Mode::Soak => println!(
            "ramcheck: one-hour sustained multi-flow soak under {} ({} pre-existing files)",
            watch_dir.display(),
            before.len()
        ),
    }

    let started = Instant::now();
    let mut rounds = 0;
    loop {
        if (mode == Mode::Verify && rounds >= VERIFY_ROUNDS)
            || (mode == Mode::Soak && started.elapsed() >= SOAK_DURATION)
        {
            break;
        }
        run_round(rounds).await;
        rounds += 1;
    }
    println!(
        "ramcheck: {rounds} full-stack rounds in {:?}",
        started.elapsed()
    );

    let after = snapshot_files(&watch_dir);
    let created: Vec<_> = after.difference(&before).cloned().collect();
    if created.is_empty() {
        println!("ramcheck PASS: zero files created; protocol state is RAM-only");
        true
    } else {
        println!("ramcheck FAIL: files created:");
        for p in &created {
            println!("  {}", p.display());
        }
        false
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mode = match parse_mode(std::env::args().skip(1)) {
        Ok(mode) => mode,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };
    if !run(mode).await {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_mode, run_round, Mode, SOAK_DURATION, VERIFY_ROUNDS};
    use std::time::Duration;

    #[test]
    fn modes_select_short_verification_or_one_hour_soak() {
        assert_eq!(parse_mode(Vec::new()).unwrap(), Mode::Verify);
        assert_eq!(parse_mode(["--soak".to_string()]).unwrap(), Mode::Soak);
        assert_eq!(VERIFY_ROUNDS, 25);
        assert_eq!(SOAK_DURATION, Duration::from_secs(60 * 60));
        assert!(parse_mode(["--unknown".to_string()]).is_err());
        assert!(parse_mode(["--soak".to_string(), "extra".to_string()]).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn short_round_exercises_all_flows() {
        run_round(0).await;
    }
}
