#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
pub mod bootstrap;
pub mod cell;
pub mod encoding;
pub mod file_stream;
pub mod fragment;
#[cfg(feature = "experimental-gc2")]
pub mod gc2;
pub mod hop;
pub mod lease;
pub mod traffic;
pub use traffic::TrafficClass;

pub use cell::{
    decode, Bucket, Cell, CellClass, CellError, CellType, APPLICATION_PAYLOAD_LIMIT, F_LAST,
    F_MORE, HEADER_LEN, MAX_MESSAGE, PROTOCOL_VERSION,
};
pub use fragment::{
    FragmentBuffer, MessageId, FRAGMENT_MESSAGE_CAP, FRAGMENT_TABLE_CAP, FRAGMENT_TOTAL_CAP,
};

pub const IDENTITY_DIGEST_SIGNATURE_DOMAIN: &[u8] = b"ghost.gc-identity-digest.v1\0";

pub fn identity_digest_signature_payload(digest: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(IDENTITY_DIGEST_SIGNATURE_DOMAIN.len() + digest.len());
    payload.extend_from_slice(IDENTITY_DIGEST_SIGNATURE_DOMAIN);
    payload.extend_from_slice(digest);
    payload
}
pub mod component;

pub mod payload_contact;

/// Reserved one-use contact packets cannot use durable or chat transports.
pub const VOLATILE_CONTACT_CONTENT_TYPE: &str = "application/vnd.ghost.payload-contact.v1";
pub const VOLATILE_FILE_CONTENT_TYPE: &str = "application/vnd.ghost.file-attempt-record.v1";
pub const VOLATILE_FILE_ACK_CONTENT_TYPE: &str = "application/vnd.ghost.file-attempt-ack.v1";
/// Durable file transfer record; the bulk scheduling producer.
pub const FILE_RECORD_CONTENT_TYPE: &str = "application/vnd.ghost.file-record.v1";
/// Durable file acknowledgement; interactive, not bulk.
pub const FILE_ACK_CONTENT_TYPE: &str = "application/vnd.ghost.file-ack.v1";
pub fn is_volatile_content_type(kind: &str) -> bool {
    [
        VOLATILE_CONTACT_CONTENT_TYPE,
        VOLATILE_FILE_CONTENT_TYPE,
        VOLATILE_FILE_ACK_CONTENT_TYPE,
        bootstrap::CONTENT_TYPE,
    ]
    .iter()
    .any(|expected| kind.eq_ignore_ascii_case(expected))
}
pub fn is_volatile_application_payload(mut bytes: &[u8]) -> bool {
    loop {
        if bytes.starts_with(b"GCPAYC1") {
            return true;
        }
        let Some((kind, body)) = component::application_parts(bytes) else {
            return false;
        };
        let media = kind.split(';').next().unwrap_or(kind);
        if is_volatile_content_type(media) {
            return true;
        }
        if media.eq_ignore_ascii_case(component::CONTENT_TYPE)
            && body.len() >= 38
            && body.starts_with(b"GCCMP1")
        {
            bytes = &body[38..];
        } else {
            return false;
        }
    }
}

/// Historical GC identity-binding signing domain. This does not grant authority.
/// The role byte and domain are retained for wire compatibility.
pub fn principal_binding_signature_payload(hash: &[u8; 32]) -> alloc::vec::Vec<u8> {
    let mut payload = alloc::vec::Vec::from(&b"ghost.principal-binding.signature.v1\0"[..]);
    payload.push(3);
    payload.extend_from_slice(hash);
    payload
}

#[cfg(test)]
mod managed_volatile_tests {
    #[test]
    fn managed_contact_bearing_kinds_are_reserved_even_in_scoped_wrappers() {
        for kind in [
            super::VOLATILE_CONTACT_CONTENT_TYPE,
            super::VOLATILE_FILE_CONTENT_TYPE,
            super::VOLATILE_FILE_ACK_CONTENT_TYPE,
            super::bootstrap::CONTENT_TYPE,
        ] {
            // Use the published application framing through the existing helper.
            let wire = crate::component::RoutedApplication {
                source: [1; 16],
                destination: [2; 16],
                application: application(kind),
            }
            .encode()
            .unwrap();
            assert!(super::is_volatile_application_payload(&wire));
            assert!(super::is_volatile_application_payload(&application(kind)));
        }
        assert!(!super::is_volatile_application_payload(&application(
            "application/vnd.ghost.file-record.v1"
        )));
    }
    fn application(kind: &str) -> Vec<u8> {
        // GCAPP1 application framing; no private contact is needed for this test.
        let mut bytes = b"GCAPP1".to_vec();
        bytes.extend_from_slice(&(kind.len() as u16).to_be_bytes());
        bytes.extend_from_slice(kind.as_bytes());
        bytes.extend_from_slice(&[0]);
        bytes
    }
}
