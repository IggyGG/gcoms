//! Aggregate desktop contribution budget across every accepted target stream.
//! The protocol profile stays unchanged; this behaves like a bounded link.
use gcoms_transport::connector::BoxStream;
use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
struct Credit {
    rate: usize,
    bytes: f64,
    updated: Option<Instant>,
}

#[derive(Default)]
pub(super) struct Budget {
    credit: Mutex<Credit>,
    transferred: AtomicU64,
}

impl Budget {
    pub fn configure(&self, rate: usize) {
        *self.credit.lock().unwrap_or_else(|p| p.into_inner()) = Credit {
            rate,
            bytes: rate as f64 / 10.0,
            updated: Some(Instant::now()),
        };
    }
    pub fn transferred(&self) -> u64 {
        self.transferred.load(Ordering::Relaxed)
    }
    fn claim(&self, requested: usize) -> usize {
        let mut credit = self.credit.lock().unwrap_or_else(|p| p.into_inner());
        if credit.rate == 0 {
            return requested;
        }
        let now = Instant::now();
        let elapsed = credit
            .updated
            .replace(now)
            .map_or(0.0, |last| now.duration_since(last).as_secs_f64());
        credit.bytes = (credit.bytes + elapsed * credit.rate as f64).min(credit.rate as f64 / 10.0);
        let admitted = requested.min(credit.bytes as usize);
        credit.bytes -= admitted as f64;
        admitted
    }
    fn finish(&self, reserved: usize, consumed: usize) {
        self.transferred
            .fetch_add(consumed as u64, Ordering::Relaxed);
        let mut credit = self.credit.lock().unwrap_or_else(|p| p.into_inner());
        if credit.rate != 0 {
            credit.bytes =
                (credit.bytes + (reserved - consumed) as f64).min(credit.rate as f64 / 10.0);
        }
    }
}

pub(super) fn wrap(
    io: BoxStream,
    budget: Arc<Budget>,
    ready: Option<Arc<AtomicBool>>,
) -> BoxStream {
    Box::new(Limited {
        io,
        budget,
        ready,
        read_wake: None,
        write_wake: None,
    })
}

struct Limited {
    io: BoxStream,
    budget: Arc<Budget>,
    ready: Option<Arc<AtomicBool>>,
    read_wake: Option<Pin<Box<tokio::time::Sleep>>>,
    write_wake: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Limited {
    fn credit(
        &mut self,
        cx: &mut Context<'_>,
        size: usize,
        write: bool,
    ) -> Poll<io::Result<usize>> {
        if self
            .ready
            .as_ref()
            .is_some_and(|ready| !ready.load(Ordering::Acquire))
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "relay contribution paused",
            )));
        }
        let admitted = self.budget.claim(size);
        // Read and write can have independent pending work. Admitting one
        // direction must not cancel the other's registered budget wakeup.
        let wake = if write {
            &mut self.write_wake
        } else {
            &mut self.read_wake
        };
        if admitted > 0 || size == 0 {
            *wake = None;
            return Poll::Ready(Ok(admitted));
        }
        if wake.is_none() {
            *wake = Some(Box::pin(tokio::time::sleep(Duration::from_millis(10))));
        }
        if let Some(timer) = wake {
            if std::future::Future::poll(timer.as_mut(), cx).is_ready() {
                *wake = Some(Box::pin(tokio::time::sleep(Duration::from_millis(10))));
                if let Some(timer) = wake {
                    let _ = std::future::Future::poll(timer.as_mut(), cx);
                }
            }
        }
        Poll::Pending
    }
}

impl AsyncRead for Limited {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let admitted = match self.credit(cx, output.remaining(), false) {
            Poll::Ready(Ok(n)) => n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        let mut bounded = ReadBuf::new(output.initialize_unfilled_to(admitted));
        let result = Pin::new(&mut self.io).poll_read(cx, &mut bounded);
        let consumed = bounded.filled().len();
        self.budget.finish(admitted, consumed);
        output.advance(consumed);
        result
    }
}

impl AsyncWrite for Limited {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let admitted = match self.credit(cx, bytes.len(), true) {
            Poll::Ready(Ok(n)) => n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        let result = Pin::new(&mut self.io).poll_write(cx, &bytes[..admitted]);
        self.budget.finish(
            admitted,
            match &result {
                Poll::Ready(Ok(n)) => *n,
                _ => 0,
            },
        );
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn opposite_direction_admission_preserves_a_pending_budget_wakeup() {
        use std::sync::atomic::AtomicUsize;
        use std::task::{Wake, Waker};
        #[derive(Default)]
        struct Wakes(AtomicUsize);
        impl Wake for Wakes {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        for blocked_write in [false, true] {
            let budget = Arc::new(Budget::default());
            budget.configure(10);
            // A different stream holds the entire one-byte burst reservation.
            let reservation = budget.claim(1);
            assert_eq!(reservation, 1);
            let (io, _peer) = tokio::io::duplex(64);
            let mut stream = wrap(Box::new(io), budget.clone(), None);
            let blocked = Arc::new(Wakes::default());
            let blocked_waker = Waker::from(blocked.clone());
            let mut blocked_context = Context::from_waker(&blocked_waker);
            let admitted_waker = Waker::from(Arc::new(Wakes::default()));
            let mut admitted_context = Context::from_waker(&admitted_waker);
            let mut bytes = [0; 1];
            if blocked_write {
                assert!(Pin::new(&mut stream)
                    .poll_write(&mut blocked_context, b"x")
                    .is_pending());
            } else {
                assert!(Pin::new(&mut stream)
                    .poll_read(&mut blocked_context, &mut ReadBuf::new(&mut bytes))
                    .is_pending());
            }
            // Returning unused credit admits only the opposite direction. Its
            // idle read or successful write must not cancel the blocked timer.
            budget.finish(reservation, 0);
            if blocked_write {
                assert!(Pin::new(&mut stream)
                    .poll_read(&mut admitted_context, &mut ReadBuf::new(&mut bytes))
                    .is_pending());
            } else {
                assert!(matches!(
                    Pin::new(&mut stream).poll_write(&mut admitted_context, b"x"),
                    Poll::Ready(Ok(1))
                ));
            }
            tokio::time::advance(Duration::from_millis(11)).await;
            tokio::task::yield_now().await;
            assert!(
                blocked.0.load(Ordering::Relaxed) > 0,
                "blocked write: {blocked_write}"
            );
        }
    }

    #[tokio::test]
    async fn paused_contribution_closes_existing_streams_and_counting_does_not_change_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let budget = Arc::new(Budget::default());
        let ready = Arc::new(AtomicBool::new(true));
        let (io, mut peer) = tokio::io::duplex(4096);
        let mut stream = wrap(Box::new(io), budget.clone(), Some(ready.clone()));
        stream
            .write_all(b"authenticated relay bytes")
            .await
            .unwrap();
        let mut bytes = [0; 25];
        peer.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"authenticated relay bytes");
        assert_eq!(budget.transferred(), 25);
        ready.store(false, Ordering::Release);
        assert_eq!(
            stream.write(b"later").await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            stream.read(&mut bytes).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(budget.transferred(), 25);
    }
    #[test]
    fn aggregate_credit_is_shared_bounded_and_unused_credit_is_returned() {
        let budget = Budget::default();
        budget.configure(100_000);
        assert_eq!(budget.claim(8_000), 8_000);
        assert!(budget.claim(8_000) < 3_000);
        budget.finish(8_000, 1_000);
        assert!(budget.claim(8_000) >= 7_000);
        assert_eq!(budget.transferred(), 1_000);
    }
}
