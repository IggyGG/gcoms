//! Published carrier loss may replace that carrier without waking unrelated
//! failed dials. Real pinned TLS and both class muxes run over in-memory I/O;
//! paused time isolates the owner's retry clock, not credential expiration.
use super::*;
use crate::gc2::{directory::BootstrapBundle, entry::lifetime_tests};
use std::sync::Mutex;
use tokio::io::DuplexStream;

type Attempts = Arc<Mutex<Vec<([u8; 32], Instant)>>>;

struct FirstConnection {
    pin: [u8; 32],
    stream: Mutex<Option<DuplexStream>>,
    attempts: Attempts,
}

impl Connector for FirstConnection {
    fn connect(&self, _: SocketAddr, pin: [u8; 32]) -> ConnectFuture<'_> {
        Box::pin(async move {
            self.attempts.lock().unwrap().push((pin, Instant::now()));
            if pin == self.pin {
                if let Some(stream) = self.stream.lock().unwrap().take() {
                    return Ok(Box::new(stream) as BoxStream);
                }
            }
            Err("fixture replacement unavailable".into())
        })
    }
}

async fn settle() {
    for _ in 0..300 {
        tokio::task::yield_now().await;
    }
}

async fn completion_case(mature: bool) {
    let (identity, mut descriptor, _peers, connect) = lifetime_tests::fixture();
    descriptor.addr = "127.0.0.1:443".parse().unwrap();
    let pin = descriptor.service_id;
    let other_pin = [2; 32];
    let first = Introduction {
        addr: descriptor.addr,
        service_id: pin,
        reentry_cap: [7; 32],
        entry_cap: descriptor.entry_cap,
        transit_cap: [8; 32],
        expires_at: descriptor.expires_at,
    };
    let mut other = first.clone();
    other.service_id = other_pin;
    other.addr = "127.0.0.2:443".parse().unwrap();
    let directory = Arc::new(Directory::for_loopback_fixture());
    directory
        .remember(
            &BootstrapBundle {
                relays: vec![first, other],
            },
            now_unix(),
        )
        .unwrap();
    directory.set_guards(vec![pin, other_pin]).unwrap();
    let (client, server_io) = tokio::io::duplex(128 * 1024);
    let server = tokio::spawn(lifetime_tests::serve(
        server_io,
        identity,
        descriptor,
        Arc::new(entry::ConnectionContext::default()),
        connect,
        lifetime_tests::Starts::default(),
        true,
    ));
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let (owner, ready) = EntryOwner::with_entry_connector(
        directory.clone(),
        CandidateProfile::file_transfer(),
        2,
        Arc::new(FirstConnection {
            pin,
            stream: Mutex::new(Some(client)),
            attempts: attempts.clone(),
        }),
    )
    .unwrap();
    let origin = Instant::now();
    let task = tokio::spawn(async move { owner.entries_loop().await });
    settle().await;
    assert_eq!(
        ready.ready_entries(),
        1,
        "pinned TLS and both muxes must publish"
    );
    assert_eq!(Instant::now(), origin);
    let count = |wanted| {
        attempts
            .lock()
            .unwrap()
            .iter()
            .filter(|(pin, _)| *pin == wanted)
            .count()
    };
    assert_eq!((count(pin), count(other_pin)), (1, 1));
    let revision = ready.readiness_revision();
    let age = if mature { 31 } else { 10 };
    tokio::time::advance(Duration::from_secs(age)).await;
    settle().await;
    let unrelated = count(other_pin);
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    settle().await;
    assert_eq!(ready.ready_entries(), 0);
    assert_eq!(ready.readiness_revision(), revision + 1);
    assert_eq!(directory.guards(), vec![pin, other_pin]);
    assert_eq!(
        count(other_pin),
        unrelated,
        "completion must not accelerate unrelated failed dials"
    );
    assert_eq!(count(pin), if mature { 2 } else { 1 }, "long-lived published carrier replacement must not await the periodic tick; short-lived failures remain paced");
    assert_eq!(Instant::now(), origin + Duration::from_secs(age));
    // The replacement failed before publication. It must not turn completion
    // handling into a dial loop or advance the published readiness revision.
    tokio::time::advance(Duration::from_secs(if mature { 29 } else { 19 })).await;
    settle().await;
    assert_eq!(count(pin), if mature { 2 } else { 1 });
    assert_eq!(count(other_pin), unrelated);
    tokio::time::advance(Duration::from_secs(1)).await;
    settle().await;
    assert_eq!(count(pin), if mature { 3 } else { 2 });
    assert_eq!(count(other_pin), unrelated + 1);
    assert_eq!(ready.readiness_revision(), revision + 1);
    eprintln!("published_age_seconds={age} replacement_attempts={} unrelated_attempts={} simulated_seconds={}", count(pin), count(other_pin), origin.elapsed().as_secs());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(ready.ready_entries(), 0);
}

#[tokio::test(start_paused = true)]
async fn long_lived_published_completion_replaces_only_its_entry_without_tick_delay() {
    completion_case(true).await;
}

#[tokio::test(start_paused = true)]
async fn short_lived_published_completion_keeps_failed_dial_pacing() {
    completion_case(false).await;
}
