use super::wait_for_retained_route;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::time::{advance, Instant};

#[tokio::test(start_paused = true)]
async fn newly_usable_retained_route_wakes_without_waiting_for_retry_tick() {
    let available = Arc::new(AtomicBool::new(false));
    let observed = available.clone();
    let start = Instant::now();
    let waiting = tokio::spawn(async move {
        wait_for_retained_route(Duration::from_secs(30), || observed.load(Ordering::SeqCst)).await;
        Instant::now()
    });
    tokio::task::yield_now().await;
    advance(Duration::from_secs(2)).await;
    assert!(!waiting.is_finished());
    available.store(true, Ordering::SeqCst);
    advance(Duration::from_millis(200)).await;
    let completed = waiting.await.unwrap();
    assert!(completed - start <= Duration::from_millis(2200));
}

#[tokio::test(start_paused = true)]
async fn unavailable_route_keeps_original_deadline_and_bounded_observation_rate() {
    let polls = AtomicUsize::new(0);
    let start = Instant::now();
    wait_for_retained_route(Duration::from_secs(30), || {
        polls.fetch_add(1, Ordering::Relaxed);
        false
    })
    .await;
    assert_eq!(start.elapsed(), Duration::from_secs(30));
    assert!(polls.load(Ordering::Relaxed) <= 151);
}

#[tokio::test(start_paused = true)]
async fn short_fixture_budget_is_not_extended_to_poll_period() {
    let start = Instant::now();
    wait_for_retained_route(Duration::from_millis(75), || false).await;
    assert_eq!(start.elapsed(), Duration::from_millis(75));
}
