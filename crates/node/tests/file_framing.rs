use gcoms_core::{component::RoutedApplication, file_stream::*, Cell, CellType};
use gcoms_crypto::IdentityKeypair;
use gcoms_node::{proto, relay::*};
use sha2::{Digest, Sha256};

#[test]
fn recommended_chunk_fits_actual_pq_frame_and_both_relay_wrappers() {
    let useful = vec![7; RECOMMENDED_CHUNK_BYTES as usize];
    let chunk = FileRecord::Chunk(FileChunk {
        profile_version: PROFILE_VERSION_V2,
        transfer_id: [1; 16],
        offset: u64::MAX - RECOMMENDED_CHUNK_BYTES,
        chunk_sha256: Sha256::digest(&useful).into(),
        data: useful,
    })
    .encode()
    .unwrap();
    let kind = b"application/vnd.ghost.file-record.v1";
    let mut application = b"GCAPP1".to_vec();
    application.extend_from_slice(&(kind.len() as u16).to_be_bytes());
    application.extend_from_slice(kind);
    application.extend_from_slice(&chunk);
    let scoped = RoutedApplication {
        source: [1; 16],
        destination: [2; 16],
        application,
    }
    .encode()
    .unwrap();
    assert!(scoped.len() <= gcoms_core::APPLICATION_PAYLOAD_LIMIT);
    let plain = proto::encode_direct_durable_data([3; 16], u64::MAX, &scoped);
    let alice = IdentityKeypair::from_seed([1; 32]);
    let bob = IdentityKeypair::from_seed([2; 32]);
    let (ab, sa) = alice.issue_bundle();
    let (bb, sb) = bob.issue_bundle();
    let (fm, mut a) =
        gcoms_crypto::initiate_authenticated(&alice, &bob.public_bytes(), &bb, b"contact").unwrap();
    let (_, mut b) = sb.accept(&fm).unwrap();
    a.provide_local_kem(sa.kem_decapsulation_key());
    b.provide_local_kem(sb.kem_decapsulation_key());
    b.provide_peer_kem(ab.kem_pub).unwrap();
    a.set_pq_policy(1, std::time::Duration::from_secs(1));
    b.receive(&a.send(b"setup").unwrap()).unwrap();
    a.receive(&b.send(b"confirmed").unwrap()).unwrap();
    let frame = a.send(&plain).unwrap();
    assert_eq!(frame.pq_ct.as_ref().unwrap().len(), 1088);
    assert!(frame.mixed_with.is_some());
    assert_eq!(
        frame.encode().len() - plain.len(),
        gcoms_crypto::session::MAX_FRAME_OVERHEAD
    );
    assert_eq!(b.receive(&frame).unwrap(), plain);
    let msg = Cell::new(
        CellType::Msg,
        0,
        0,
        proto::encode_frame(&alice.public_bytes(), &frame),
    );
    assert!(msg.payload.len() <= gcoms_core::MAX_MESSAGE);
    let push = RelayPush {
        queue_id: [4; 32],
        epoch: 1,
        push_nonce: [5; 16],
        push_expiry: u64::MAX,
        msg: Some(msg.clone()),
    }
    .encode_into_cell(&[6; 32], &[7; 32])
    .unwrap();
    let frwd = Frwd {
        target: RelayTarget {
            address: "192.0.2.1:443".parse().unwrap(),
            relay_service_id: [7; 32],
        },
        frwd_expiry: u64::MAX,
        relay_push: Some(UnauthenticatedRelayPush::parse(push.clone()).unwrap()),
        nonce: [8; 16],
    }
    .encode_into_cell_with_policy(&[9; 32], &[10; 32], &FrwdTargetPolicy::new(true))
    .unwrap();
    assert_eq!(frwd.encode_wire().unwrap().len(), 16 * 1024);
    assert!(gcoms_core::HEADER_LEN + frwd.payload.len() <= 16 * 1024);
    assert_eq!(
        checkpoint_batch_chunks(32 * 8192, RECOMMENDED_CHUNK_BYTES).unwrap(),
        23
    );
    assert_eq!(
        checkpoint_batch_chunks(u64::MAX, RECOMMENDED_CHUNK_BYTES).unwrap(),
        32
    );
    println!("useful={} file={} component_application={} direct={} frame={} MSG={} RELAY_PUSH={} FRWD={} wire={}",
        RECOMMENDED_CHUNK_BYTES, chunk.len(), scoped.len(), plain.len(), frame.encode().len(),
        msg.payload.len()+6, push.payload.len()+6, frwd.payload.len()+6, frwd.encode_wire().unwrap().len());
}
