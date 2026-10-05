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
        wake: None,
    })
}

struct Limited {
    io: BoxStream,
    budget: Arc<Budget>,
    ready: Option<Arc<AtomicBool>>,
    wake: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Limited {
    fn credit(&mut self, cx: &mut Context<'_>, size: usize) -> Poll<io::Result<usize>> {
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
        if admitted > 0 || size == 0 {
            self.wake = None;
            return Poll::Ready(Ok(admitted));
        }
        if self.wake.is_none() {
            self.wake = Some(Box::pin(tokio::time::sleep(Duration::from_millis(10))));
        }
        if let Some(wake) = &mut self.wake {
            if std::future::Future::poll(wake.as_mut(), cx).is_ready() {
                self.wake = Some(Box::pin(tokio::time::sleep(Duration::from_millis(10))));
                if let Some(wake) = &mut self.wake {
                    let _ = std::future::Future::poll(wake.as_mut(), cx);
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
        let admitted = match self.credit(cx, output.remaining()) {
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
        let admitted = match self.credit(cx, bytes.len()) {
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
