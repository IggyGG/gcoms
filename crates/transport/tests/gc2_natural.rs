#![cfg(feature = "experimental-gc2")]
use bytes::Bytes;
use gcoms_core::{gc2::NaturalCell, CellType, TrafficClass};
use gcoms_transport::{
    gc2::{status_cell, NaturalOutcome, NaturalRoute},
    server::{AcceptedDuplex, Tp1Server},
    tls::TlsIdentity,
    HopReply, TokenRegistry, Tp1Client,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::oneshot;

struct Fixture {
    address: SocketAddr,
    pin: [u8; 32],
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}
impl Fixture {
    async fn new(mut responses: Vec<Vec<u8>>, fragment: usize) -> Self {
        let identity = TlsIdentity::generate().unwrap();
        let registry = TokenRegistry::new();
        registry.insert_post("legacy");
        let mut response = Vec::new();
        for bytes in responses.drain(..) {
            response.extend(bytes);
        }
        let response = Bytes::from(response);
        let handler = Arc::new(move |token: &str| {
            if token != "natural" {
                return None;
            }
            let response = response.clone();
            let accepted: AcceptedDuplex = Box::new(move |mut body, mut send| {
                Box::pin(async move {
                    gcoms_transport::server::read_body(&mut body, 16 * 1024)
                        .await
                        .unwrap();
                    let mut send = send
                        .send_response(
                            http::Response::builder().status(200).body(()).unwrap(),
                            false,
                        )
                        .unwrap();
                    let count = response.len().div_ceil(fragment);
                    for (index, chunk) in response.chunks(fragment).enumerate() {
                        if send
                            .send_data(Bytes::copy_from_slice(chunk), index + 1 == count)
                            .is_err()
                        {
                            break;
                        }
                    }
                })
            });
            Some(accepted)
        });
        let server = Tp1Server::bind_with_identity(
            "127.0.0.1:0".parse().unwrap(),
            registry,
            Arc::new(|_, _| Ok(None)),
            Arc::new(|_| None),
            &identity,
        )
        .await
        .unwrap()
        .with_duplex(handler);
        let address = server.local_addr().unwrap();
        let (stop, rx) = oneshot::channel();
        let task = tokio::spawn(server.run_until(async {
            let _ = rx.await;
        }));
        Self {
            address,
            pin: identity.service_id(),
            stop,
            task,
        }
    }
    fn route(&self, token: &'static str) -> NaturalRoute<'static> {
        NaturalRoute {
            addr: self.address,
            service_id: self.pin,
            token,
            excluded: &[],
            class: TrafficClass::Bulk,
        }
    }
    async fn finish(self) {
        self.stop.send(()).unwrap();
        self.task.await.unwrap().unwrap();
    }
}
fn request() -> gcoms_transport::client::Result<NaturalCell> {
    Ok(NaturalCell::new(CellType::RelaySub, 0, vec![1; 100]).unwrap())
}

#[tokio::test]
async fn natural_finite_status_and_legacy_wire_are_explicitly_separate() {
    for reply in [
        HopReply::Accepted,
        HopReply::Conflict,
        HopReply::Overloaded,
        HopReply::Internal,
    ] {
        let fixture = Fixture::new(vec![status_cell(reply).encode()], 3).await;
        let client = Tp1Client::new().unwrap();
        let result = client
            .post_natural_prepared(fixture.route("natural"), request)
            .await
            .unwrap();
        let mut wrong_class = fixture.route("natural");
        wrong_class.class = TrafficClass::Interactive;
        assert!(client
            .post_natural_prepared(wrong_class, request)
            .await
            .is_err());
        assert_eq!(
            result,
            match reply {
                HopReply::Accepted => NaturalOutcome::Accepted(None),
                HopReply::Conflict => NaturalOutcome::Conflict,
                HopReply::Overloaded => NaturalOutcome::Overloaded,
                HopReply::Internal => NaturalOutcome::Internal,
            }
        );
        // A legacy endpoint rejects the GC/2 request before authentication.
        assert_eq!(
            client
                .post_natural_prepared(fixture.route("legacy"), request)
                .await
                .unwrap(),
            NaturalOutcome::Decoy(404)
        );
        assert!(client
            .post_cell_pinned(
                fixture.address,
                fixture.pin,
                "natural",
                Bytes::from(request().unwrap().encode())
            )
            .await
            .is_err());
        fixture.finish().await;
    }
    let fixture = Fixture::new(vec![HopReply::Accepted.cell().encode_wire().unwrap()], 4096).await;
    let client = Tp1Client::new().unwrap();
    assert!(client
        .post_natural_prepared(fixture.route("natural"), request)
        .await
        .is_err());
    fixture.finish().await;
}

#[tokio::test]
async fn natural_stream_reassembles_fragmented_and_coalesced_cells() {
    let small = NaturalCell::new(CellType::Msg, 0, vec![17; 128]).unwrap();
    let large = NaturalCell::new(CellType::Msg, 0, vec![19; 15 * 1024]).unwrap();
    for fragment in [1, 37, 16384] {
        // Byte-wise framing exercises headers and small messages without
        // exceeding HTTP/2's independent tiny-frame flood limit.
        let mut replies = vec![status_cell(HopReply::Accepted).encode(), small.encode()];
        if fragment > 1 {
            replies.push(large.encode());
        }
        let fixture = Fixture::new(replies, fragment).await;
        let client = Tp1Client::new().unwrap();
        let mut stream = client
            .open_natural_prepared(
                fixture.route("natural"),
                tokio::time::Instant::now() + Duration::from_secs(10),
                request,
            )
            .await
            .unwrap();
        assert_eq!(stream.recv().await.unwrap().unwrap(), small);
        if fragment > 1 {
            assert_eq!(stream.recv().await.unwrap().unwrap(), large);
        }
        assert!(stream.recv().await.is_none());
        fixture.finish().await;
    }
}

#[tokio::test]
async fn malformed_streams_fail_closed_without_returning_partial_messages() {
    let good = NaturalCell::new(CellType::Msg, 0, vec![17; 128])
        .unwrap()
        .encode();
    let mut reserved = good.clone();
    reserved[2] = 1;
    let mut huge = good[..6].to_vec();
    huge[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
    let wrong_version = HopReply::Accepted.cell().encode_wire().unwrap();
    let bad_status = NaturalCell::new(CellType::Ack, 0, vec![9, 0])
        .unwrap()
        .encode();
    for bad in [
        good[..3].to_vec(),
        good[..30].to_vec(),
        reserved,
        huge,
        wrong_version,
        bad_status,
    ] {
        let fixture = Fixture::new(vec![status_cell(HopReply::Accepted).encode(), bad], 7).await;
        let client = Tp1Client::new().unwrap();
        let mut stream = client
            .open_natural_prepared(
                fixture.route("natural"),
                tokio::time::Instant::now() + Duration::from_secs(10),
                request,
            )
            .await
            .unwrap();
        assert!(stream.recv().await.unwrap().is_err());
        assert!(stream.recv().await.is_none());
        fixture.finish().await;
    }
    for bad in [status_cell(HopReply::Conflict).encode(), good] {
        let fixture = Fixture::new(vec![bad], 1024).await;
        let client = Tp1Client::new().unwrap();
        assert!(client
            .open_natural_prepared(
                fixture.route("natural"),
                tokio::time::Instant::now() + Duration::from_secs(10),
                request,
            )
            .await
            .is_err());
        fixture.finish().await;
    }
}
