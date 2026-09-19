//! Established GCT2 channels. The owner authenticates and exchanges `Open`
//! before running this pump, supplies bounded local I/O, and owns cancellation
//! and the absolute connection lifetime. Starting/stopping an interactive pump
//! in response to chat activity would defeat its traffic protection.
use super::{CoverMode, RecordCodec, RecordKind, HEADER_LEN};
use rand::Rng;
use std::{future::poll_fn, io, pin::Pin, task::Poll};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    time::{sleep_until, Instant},
};

/// Record-layer accounting only: excludes TLS, H2, TCP, and link overhead.
/// Payload bytes are opaque circuit fragments, not application delivery.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordCounts {
    pub records: u64,
    pub wire_bytes: u64,
    pub payload_bytes: u64,
}

impl RecordCounts {
    fn add(&mut self, wire: usize, payload: usize) {
        self.records = self.records.saturating_add(1);
        self.wire_bytes = self.wire_bytes.saturating_add(wire as u64);
        self.payload_bytes = self.payload_bytes.saturating_add(payload as u64);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChannelCounts {
    pub sent: RecordCounts,
    pub received: RecordCounts,
}

/// Forward one already-open channel in both directions, without detached tasks.
/// The authenticated profile selects full cover or protected interactive slots
/// with immediately eligible bulk. Jitter changes slot phase independently of
/// payload arrivals. Blocked writes never accumulate catch-up bursts.
///
/// The owner must keep both class channels alive for its traffic-independent
/// connected period and reserve interactive transport credit separately. This
/// pump alone does not provide a multiplexed or qualified private connection.
pub async fn pump<W, L>(
    wire: W,
    local: L,
    codec: RecordCodec,
    first_slot: Instant,
) -> io::Result<ChannelCounts>
where
    W: AsyncRead + AsyncWrite + Unpin,
    L: AsyncRead + AsyncWrite + Unpin,
{
    let (wire_read, wire_write) = tokio::io::split(wire);
    let (local_read, local_write) = tokio::io::split(local);
    let (sent, received) = tokio::try_join!(
        write_records(wire_write, local_read, codec, first_slot),
        read_records(wire_read, local_write, codec),
    )?;
    Ok(ChannelCounts { sent, received })
}

async fn write_records<W, R>(
    mut wire: W,
    mut local: R,
    codec: RecordCodec,
    first_slot: Instant,
) -> io::Result<RecordCounts>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut payload = vec![0; codec.payload_limit()];
    let mut encoded = Vec::new();
    let mut counts = RecordCounts::default();
    let mut next_slot = first_slot + slot_phase(codec);
    loop {
        let ready = if codec.unshaped_bulk() {
            Some(local.read(&mut payload).await?)
        } else {
            sleep_until(next_slot).await;
            poll_fn(|cx| {
                let mut buf = ReadBuf::new(&mut payload);
                Poll::Ready(match Pin::new(&mut local).poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(())) => Ok(Some(buf.filled().len())),
                    Poll::Ready(Err(error)) => Err(error),
                    Poll::Pending => Ok(None),
                })
            })
            .await?
        };
        let (kind, len) = match ready {
            None => (RecordKind::Cover, 0),
            Some(0) => (RecordKind::Close, 0),
            Some(len) => (RecordKind::Data, len),
        };
        codec
            .encode_into(kind, &payload[..len], &mut encoded)
            .map_err(invalid)?;
        wire.write_all(&encoded).await?;
        wire.flush().await?;
        counts.add(encoded.len(), len);
        if kind == RecordKind::Close {
            wire.shutdown().await?;
            return Ok(counts);
        }
        // Always choose the next *future* point on the original lattice.
        // Interval::Skip can produce one immediate late tick after a blocked
        // write; that would unnecessarily bunch two records together.
        let now = Instant::now();
        let period = codec.profile().period();
        let elapsed = now.saturating_duration_since(first_slot);
        let remainder = elapsed.as_nanos() % period.as_nanos();
        next_slot =
            now + period - std::time::Duration::from_nanos(remainder as u64) + slot_phase(codec);
    }
}

fn slot_phase(codec: RecordCodec) -> std::time::Duration {
    if codec.profile().mode() == CoverMode::InteractiveJitter && !codec.unshaped_bulk() {
        // Independent phase in [0, period/4]. Consecutive unblocked intervals
        // lie in [3*period/4, 5*period/4], with the same long-run mean rate.
        let maximum = codec.profile().period().as_micros() as u64 / 4;
        std::time::Duration::from_micros(rand::thread_rng().gen_range(0..=maximum))
    } else {
        std::time::Duration::ZERO
    }
}

async fn read_records<R, W>(
    mut wire: R,
    mut local: W,
    codec: RecordCodec,
) -> io::Result<RecordCounts>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut header = [0; HEADER_LEN];
    let mut buffer = Vec::new();
    let mut counts = RecordCounts::default();
    loop {
        wire.read_exact(&mut header).await?;
        let length = codec.wire_len(&header).map_err(invalid)?;
        buffer.resize(length, 0);
        buffer[..HEADER_LEN].copy_from_slice(&header);
        wire.read_exact(&mut buffer[HEADER_LEN..]).await?;
        let record = codec.decode(&buffer).map_err(invalid)?;
        match record.kind() {
            RecordKind::Data => local.write_all(record.payload()).await?,
            RecordKind::Cover => (),
            RecordKind::Close => {
                // Close is a half-close, not permission to ignore trailing data.
                let mut trailing = [0];
                if wire.read(&mut trailing).await? != 0 {
                    return Err(invalid("bytes after GCT2 close"));
                }
                local.shutdown().await?;
                counts.add(length, 0);
                return Ok(counts);
            }
            RecordKind::Open => return Err(invalid("GCT2 channel already open")),
        }
        counts.add(length, record.payload().len());
    }
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gc2::{CandidateProfile, MAX_RECORD};
    use gcoms_core::TrafficClass;
    use std::time::Duration;

    fn codec(class: TrafficClass) -> RecordCodec {
        RecordCodec::new(class, CandidateProfile::new(1024, 250).unwrap())
    }

    async fn trace(burst: bool) -> (Vec<(Duration, usize)>, Vec<u8>) {
        let codec = codec(TrafficClass::Interactive);
        let (mut application, local) = tokio::io::duplex(8192);
        let (wire, mut observer) = tokio::io::duplex(8192);
        let origin = Instant::now();
        let writer = tokio::spawn(write_records(
            wire,
            local,
            codec,
            origin + codec.profile().period(),
        ));
        let mut times = Vec::new();
        let mut received = Vec::new();
        for slot in 0..8 {
            if burst && slot == 2 {
                // Includes fragmentation across several fixed-size records.
                application.write_all(&vec![37; 2800]).await.unwrap();
            }
            let mut bytes = vec![0; codec.profile().record_len()];
            observer.read_exact(&mut bytes).await.unwrap();
            times.push((origin.elapsed(), bytes.len()));
            received.extend_from_slice(codec.decode(&bytes).unwrap().payload());
        }
        writer.abort();
        assert!(writer.await.unwrap_err().is_cancelled());
        (times, received)
    }

    #[tokio::test(start_paused = true)]
    async fn idle_and_burst_have_identical_interactive_opportunities() {
        let (idle, idle_bytes) = trace(false).await;
        let (burst, burst_bytes) = trace(true).await;
        assert_eq!(idle, burst);
        assert_eq!(idle.len(), 8);
        for (index, (at, length)) in idle.into_iter().enumerate() {
            assert_eq!(at, Duration::from_millis((index as u64 + 1) * 250));
            assert_eq!(length, 1024);
        }
        assert!(idle_bytes.is_empty());
        assert_eq!(burst_bytes, vec![37; 2800]);
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_write_skips_slots_without_catchup() {
        let codec = codec(TrafficClass::Interactive);
        let (_application, local) = tokio::io::duplex(8192);
        let (wire, mut observer) = tokio::io::duplex(1);
        let origin = Instant::now();
        let writer = tokio::spawn(write_records(
            wire,
            local,
            codec,
            origin + codec.profile().period(),
        ));
        tokio::time::advance(Duration::from_millis(250)).await;
        tokio::task::yield_now().await;
        // Block almost four opportunities, then consume the partial write.
        tokio::time::advance(Duration::from_millis(980)).await;
        let mut record = vec![0; 1024];
        observer.read_exact(&mut record).await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(origin.elapsed(), Duration::from_millis(1230));
        observer.read_exact(&mut record).await.unwrap();
        assert_eq!(origin.elapsed(), Duration::from_millis(1250));
        writer.abort();
        assert!(writer.await.unwrap_err().is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn bulk_rides_the_same_lattice_and_covers_when_idle() {
        let codec = codec(TrafficClass::Bulk);
        let (mut application, local) = tokio::io::duplex(MAX_RECORD * 2);
        let (wire, mut observer) = tokio::io::duplex(MAX_RECORD * 4);
        let origin = Instant::now();
        let period = codec.profile().period();
        let writer = tokio::spawn(write_records(wire, local, codec, origin));
        // The first two slots are idle: they emit padded cover records with no
        // payload, exactly like the interactive lattice.
        for _ in 0..2 {
            let mut bytes = vec![0; codec.profile().record_len()];
            observer.read_exact(&mut bytes).await.unwrap();
            assert_eq!(codec.decode(&bytes).unwrap().kind(), RecordKind::Cover);
        }
        // Data written between slots is emitted at the next slot, one record
        // per slot, never immediately.
        application.write_all(&vec![19; MAX_RECORD]).await.unwrap();
        application.shutdown().await.unwrap();
        let mut got = Vec::new();
        loop {
            let mut bytes = vec![0; codec.profile().record_len()];
            observer.read_exact(&mut bytes).await.unwrap();
            let record = codec.decode(&bytes).unwrap();
            if record.kind() == RecordKind::Close {
                break;
            }
            if record.kind() == RecordKind::Data {
                got.extend_from_slice(record.payload());
            }
        }
        assert_eq!(got, vec![19; MAX_RECORD]);
        let counts = writer.await.unwrap().unwrap();
        assert_eq!(counts.payload_bytes, MAX_RECORD as u64);
        assert!(counts.records >= 3);
        let _ = period;
    }

    #[tokio::test(start_paused = true)]
    async fn interactive_cover_profile_sends_bulk_immediately_without_idle_records() {
        let profile = super::super::CandidateProfile::new(1024, 1500)
            .unwrap()
            .with_mode(CoverMode::Interactive);
        let codec = RecordCodec::new(TrafficClass::Bulk, profile);
        let (mut application, local) = tokio::io::duplex(MAX_RECORD * 2);
        let (wire, mut observer) = tokio::io::duplex(MAX_RECORD * 2);
        let writer = tokio::spawn(write_records(
            wire,
            local,
            codec,
            Instant::now() + std::time::Duration::from_secs(30),
        ));
        let mut header = [0; HEADER_LEN];
        assert!(tokio::time::timeout(
            std::time::Duration::from_secs(2),
            observer.read_exact(&mut header)
        )
        .await
        .is_err());
        let payload = vec![42; 11 * 1024];
        application.write_all(&payload).await.unwrap();
        tokio::time::timeout(
            std::time::Duration::from_millis(1),
            observer.read_exact(&mut header),
        )
        .await
        .unwrap()
        .unwrap();
        let mut wire = vec![0; codec.wire_len(&header).unwrap()];
        wire[..HEADER_LEN].copy_from_slice(&header);
        observer.read_exact(&mut wire[HEADER_LEN..]).await.unwrap();
        assert_eq!(codec.decode(&wire).unwrap().payload(), payload);
        application.shutdown().await.unwrap();
        observer.read_exact(&mut header).await.unwrap();
        assert_eq!(codec.decode(&header).unwrap().kind(), RecordKind::Close);
        let counts = writer.await.unwrap().unwrap();
        assert_eq!(counts.records, 2);
        assert_eq!(counts.wire_bytes, (payload.len() + 2 * HEADER_LEN) as u64);
    }

    #[tokio::test(start_paused = true)]
    async fn independent_jitter_keeps_idle_interactive_slots_bounded() {
        let profile = super::super::CandidateProfile::new(1024, 1000)
            .unwrap()
            .with_mode(CoverMode::InteractiveJitter);
        let codec = RecordCodec::new(TrafficClass::Interactive, profile);
        let (_application, local) = tokio::io::duplex(MAX_RECORD);
        let (wire, mut observer) = tokio::io::duplex(MAX_RECORD);
        let origin = Instant::now();
        let writer = tokio::spawn(write_records(wire, local, codec, origin + profile.period()));
        let mut previous = None;
        for _ in 0..32 {
            let mut wire = vec![0; profile.record_len()];
            observer.read_exact(&mut wire).await.unwrap();
            assert_eq!(codec.decode(&wire).unwrap().kind(), RecordKind::Cover);
            let now = Instant::now();
            if let Some(last) = previous {
                let interval = now - last;
                // Tokio's timer has millisecond resolution.
                assert!(interval >= std::time::Duration::from_millis(749));
                assert!(interval <= std::time::Duration::from_millis(1251));
            }
            previous = Some(now);
        }
        writer.abort();
        assert!(writer.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn validates_whole_record_before_exposing_payload() {
        let codec = codec(TrafficClass::Interactive);
        let good = codec.encode(RecordKind::Data, b"must not escape").unwrap();
        let mut padding = good.clone();
        *padding.last_mut().unwrap() = 1;
        let mut huge = good[..HEADER_LEN].to_vec();
        huge[7..9].copy_from_slice(&u16::MAX.to_be_bytes());
        for malformed in [
            padding,
            huge,
            good[..good.len() - 1].to_vec(),
            codec.encode(RecordKind::Open, &[]).unwrap(),
        ] {
            let (mut input, wire) = tokio::io::duplex(8192);
            let (local, mut output) = tokio::io::duplex(8192);
            input.write_all(&malformed).await.unwrap();
            input.shutdown().await.unwrap();
            assert!(read_records(wire, local, codec).await.is_err());
            let mut leaked = Vec::new();
            output.read_to_end(&mut leaked).await.unwrap();
            assert!(leaked.is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn fragmented_records_preserve_half_close_and_reply() {
        let codec = codec(TrafficClass::Bulk);
        let (mut client, client_local) = tokio::io::duplex(7);
        let (mut server, server_local) = tokio::io::duplex(11);
        let (client_wire, server_wire) = tokio::io::duplex(13);
        let client_pump = pump(client_wire, client_local, codec, Instant::now());
        let server_pump = pump(server_wire, server_local, codec, Instant::now());
        let client_work = async {
            client.write_all(&[7; 123]).await.unwrap();
            client.shutdown().await.unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, vec![9; 215]);
        };
        let server_work = async {
            let mut request = Vec::new();
            server.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, vec![7; 123]);
            server.write_all(&[9; 215]).await.unwrap();
            server.shutdown().await.unwrap();
        };
        let (client_counts, server_counts, (), ()) =
            tokio::join!(client_pump, server_pump, client_work, server_work);
        let (client_counts, server_counts) = (client_counts.unwrap(), server_counts.unwrap());
        assert_eq!(client_counts.sent, server_counts.received);
        assert_eq!(server_counts.sent, client_counts.received);
        assert_eq!(client_counts.sent.payload_bytes, 123);
        assert_eq!(server_counts.sent.payload_bytes, 215);
    }

    #[tokio::test]
    async fn trailing_data_after_close_is_rejected() {
        let codec = codec(TrafficClass::Bulk);
        let mut wire = codec.encode(RecordKind::Close, &[]).unwrap();
        wire.push(1);
        assert_eq!(
            read_records(wire.as_slice(), tokio::io::sink(), codec)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}
