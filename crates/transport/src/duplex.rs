//! Byte I/O for one established HTTP/2 stream. The caller owns connection
//! authentication, its driver and resource limits. This adapter adds no padding.
use bytes::Bytes;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Bound each queued write independently of the caller's buffer size.
pub const MAX_WRITE_CHUNK: usize = 16 * 1024;

/// Backpressure follows HTTP/2 credit in both directions. Receive credit is
/// returned only for bytes consumed by the caller, not when a frame arrives.
/// Dropping an unfinished stream cancels it; write shutdown preserves reading.
pub struct H2Stream {
    receive: h2::RecvStream,
    send: h2::SendStream<Bytes>,
    pending: Bytes,
    read_closed: bool,
    write_closed: bool,
}

impl H2Stream {
    pub fn new(receive: h2::RecvStream, send: h2::SendStream<Bytes>) -> Self {
        Self {
            receive,
            send,
            pending: Bytes::new(),
            read_closed: false,
            write_closed: false,
        }
    }

    /// Observe peer cancellation while awaiting work that does not otherwise
    /// read or write this stream (for example an admitted target connection).
    pub fn poll_reset(&mut self, cx: &mut Context<'_>) -> Poll<Result<h2::Reason, h2::Error>> {
        self.send.poll_reset(cx)
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // Empty DATA frames consume no flow-control credit. Bound polling work
        // even when a peer queues many of them before the next useful byte.
        for _ in 0..16 {
            if !self.pending.is_empty() {
                let count = buf.remaining().min(self.pending.len());
                if let Err(error) = self.receive.flow_control().release_capacity(count) {
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                buf.put_slice(&self.pending.split_to(count));
                return Poll::Ready(Ok(()));
            }
            if self.read_closed {
                return Poll::Ready(Ok(()));
            }
            match self.receive.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(bytes))) => self.pending = bytes,
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(io::Error::other(error))),
                Poll::Ready(None) => self.read_closed = true,
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let wanted = buf.len().min(MAX_WRITE_CHUNK);
        self.send.reserve_capacity(wanted);
        while self.send.capacity() == 0 {
            match self.send.poll_capacity(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(_))) => {}
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(io::Error::other(error))),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "stream closed",
                    )));
                }
            }
        }
        let count = wanted.min(self.send.capacity());
        match self
            .send
            .send_data(Bytes::copy_from_slice(&buf[..count]), false)
        {
            Ok(()) => Poll::Ready(Ok(count)),
            Err(error) => Poll::Ready(Err(io::Error::other(error))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // There is no adapter-side write buffer; accepted bytes belong to the
        // continuously polled connection driver. This is not a delivery receipt.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        self.write_closed = true;
        Poll::Ready(
            self.send
                .send_data(Bytes::new(), true)
                .map_err(io::Error::other),
        )
    }
}

impl Drop for H2Stream {
    fn drop(&mut self) {
        if !self.read_closed || !self.write_closed {
            self.send.send_reset(h2::Reason::CANCEL);
        }
    }
}
