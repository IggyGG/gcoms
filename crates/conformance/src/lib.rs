use gcoms_core::file_stream::{
    AckCode, AckStage, Contact, FileAck, FileChunk, FileContact, FileFinish, FileInit, FileRecord,
    PROFILE_VERSION_V1,
};
use gcoms_core::{Cell, CellType};
use gcoms_crypto::IdentityKeypair;
use gcoms_mls::{Caps, Invite};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const VECTORS: &str = include_str!("../vectors/gc1-v1.txt");

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn computed() -> Result<BTreeMap<String, String>, String> {
    let mut values = BTreeMap::new();
    values.insert(
        "protocol.version".into(),
        gcoms_core::PROTOCOL_VERSION.to_string(),
    );

    let cell = Cell::new(CellType::Msg, 0x03, 0x1234, b"GC/1 cell vector".to_vec());
    let cell_wire = cell.encode_wire().map_err(|error| error.to_string())?;
    if gcoms_core::decode(&cell_wire).map_err(|error| error.to_string())? != cell {
        return Err("cell vector did not round-trip".into());
    }
    values.insert("protocol.cell.sha256".into(), digest(&cell_wire));
    values.insert("protocol.cell.length".into(), cell_wire.len().to_string());

    let file_digest: [u8; 32] = Sha256::digest(b"GC/1 file vector").into();
    let contact = Contact {
        address: "203.0.113.8:443"
            .parse()
            .map_err(|error| format!("{error}"))?,
        relay_service_id: [0x11; 32],
        queue_id: [0x22; 32],
        epoch: 7,
        push_cap: [0x33; 32],
        lease_expiry: 2_000,
    };
    let file_contact = FileContact {
        profile_version: PROFILE_VERSION_V1,
        transfer_id: [0x44; 16],
        recipient_contact: contact.clone(),
        file_cap: [0x55; 32],
        contact_expiry: 1_900,
        max_file_size: 1_024,
        max_chunk_size: 512,
        max_inflight_bytes: 1_024,
    };
    let mut init = FileInit {
        profile_version: PROFILE_VERSION_V1,
        transfer_id: file_contact.transfer_id,
        file_size: 16,
        chunk_size: 16,
        file_sha256: file_digest,
        ack_route: contact,
        init_nonce: [0x66; 16],
        bearer_proof: [0; 32],
    };
    init.set_bearer_proof(&file_contact)
        .map_err(|error| error.to_string())?;
    let file_records = [
        ("init", FileRecord::Init(init)),
        (
            "chunk",
            FileRecord::Chunk(FileChunk {
                profile_version: PROFILE_VERSION_V1,
                transfer_id: file_contact.transfer_id,
                offset: 0,
                chunk_sha256: file_digest,
                data: b"GC/1 file vector".to_vec(),
            }),
        ),
        (
            "finish",
            FileRecord::Finish(FileFinish {
                profile_version: PROFILE_VERSION_V1,
                transfer_id: file_contact.transfer_id,
                file_size: 16,
                file_sha256: file_digest,
            }),
        ),
        (
            "ack",
            FileRecord::Ack(FileAck {
                profile_version: PROFILE_VERSION_V1,
                transfer_id: file_contact.transfer_id,
                stage: AckStage::Complete,
                code: AckCode::Ok,
                received_size: 16,
                file_sha256: file_digest,
            }),
        ),
    ];
    for (name, record) in file_records {
        let wire = record.encode().map_err(|error| error.to_string())?;
        values.insert(format!("protocol.file.{name}.sha256"), digest(&wire));
    }

    let b64_input: Vec<u8> = (0..32).collect();
    let b64 = gcoms_transport::encode_b64url(&b64_input);
    if gcoms_transport::decode_b64url(&b64).as_deref() != Some(b64_input.as_slice()) {
        return Err("base64url vector did not round-trip".into());
    }
    values.insert("transport.base64url".into(), b64);

    for (name, value) in gcoms_crypto::conformance::transcript().map_err(|e| e.to_string())? {
        values.insert(name.into(), value);
    }

    let owner = IdentityKeypair::from_seed([0xaa; 32]);
    let mut invite = Invite {
        channel: owner.public_bytes(),
        leaf: gcoms_mls::invite::leaf_hash(b"GC/1 key package vector"),
        name: "vector-member".into(),
        caps: Caps::admin(),
        expiry: 0x1122_3344_5566_7788,
        sig: Vec::new(),
    };
    invite.sig = owner.sign(&invite.signing_payload());
    let invite_wire = invite.encode();
    if Invite::decode(&invite_wire) != Some(invite) {
        return Err("invite vector did not round-trip".into());
    }
    values.insert("mls.invite.sha256".into(), digest(&invite_wire));
    values.insert(
        "mls.ciphersuite.id".into(),
        format!("{:04x}", gcoms_mls::CIPHERSUITE_ID),
    );
    values.insert(
        "mls.ciphersuite.profile".into(),
        "ML-KEM768+X25519/AES-128-GCM/SHA-256/Ed25519".into(),
    );

    Ok(values)
}

fn expected(input: &str) -> Result<BTreeMap<String, String>, String> {
    input
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let line = line.trim();
            (!line.is_empty() && !line.starts_with('#')).then_some((index + 1, line))
        })
        .map(|(line_number, line)| {
            let (name, value) = line
                .split_once('=')
                .ok_or_else(|| format!("invalid vector line {line_number}"))?;
            Ok((name.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

pub fn verify(input: &str) -> Result<usize, String> {
    let expected = expected(input)?;
    let actual = computed()?;
    if expected != actual {
        for (name, value) in &actual {
            if expected.get(name) != Some(value) {
                return Err(format!(
                    "vector mismatch for {name}: expected {:?}, computed {value}",
                    expected.get(name)
                ));
            }
        }
        return Err("vector file contains missing or unexpected entries".into());
    }
    Ok(actual.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gc1_v1_vectors_conform() {
        assert_eq!(verify(VECTORS).unwrap(), 19);
    }

    #[test]
    fn malformed_mls_artifacts_do_not_claim_the_required_suite() {
        assert_eq!(gcoms_mls::ciphersuite_of_key_package(&[]), None);
        assert_eq!(gcoms_mls::ciphersuite_of_key_package(&[0; 64]), None);
        assert_eq!(gcoms_mls::ciphersuite_of_welcome(&[0; 64]), None);
    }
}
