use gcoms_mobile::*;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

struct Session(u64);
impl Session {
    fn new() -> Self {
        let value = gcoms_mobile_create();
        assert_ne!(value, 0);
        Self(value)
    }
    fn submit(&self, bytes: &[u8]) -> u64 {
        unsafe { gcoms_mobile_submit(self.0, bytes.as_ptr(), bytes.len()) }
    }
    fn request(&self, request: Value) -> Value {
        let ticket = self.submit(&serde_json::to_vec(&request).unwrap());
        assert_ne!(ticket, 0);
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let length = unsafe { gcoms_mobile_take(self.0, ticket, std::ptr::null_mut(), 0) };
            assert!(length >= 0);
            if length > 0 {
                let mut bytes = vec![0; length as usize];
                assert_eq!(
                    unsafe { gcoms_mobile_take(self.0, ticket, bytes.as_mut_ptr(), bytes.len()) },
                    length
                );
                assert_eq!(
                    unsafe { gcoms_mobile_take(self.0, ticket, std::ptr::null_mut(), 0) },
                    -1
                );
                return serde_json::from_slice(&bytes).unwrap();
            }
            assert!(Instant::now() < deadline, "native operation timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        assert_eq!(gcoms_mobile_destroy(self.0), 0);
    }
}
#[test]
fn invalid_inputs_cancel_and_owned_result_lifetime() {
    assert_eq!(gcoms_mobile_abi_version(), 1);
    let session = Session::new();
    assert_eq!(
        unsafe { gcoms_mobile_submit(session.0, std::ptr::null(), 1) },
        0
    );
    assert_eq!(
        unsafe { gcoms_mobile_submit(session.0, b"x".as_ptr(), MAX_REQUEST + 1) },
        0
    );
    assert!(session
        .request(json!({"op": "identity"}))
        .get("error")
        .is_some());
    assert!(session
        .request(json!({"op": "unrecognized"}))
        .get("error")
        .is_some());
    let ticket = session.submit(b"{}");
    assert_ne!(ticket, 0);
    assert_eq!(gcoms_mobile_cancel(session.0, ticket), 0);
    assert_eq!(gcoms_mobile_cancel(session.0, ticket), -1);
    assert_eq!(
        unsafe { gcoms_mobile_take(session.0, ticket, std::ptr::null_mut(), 0) },
        -1
    );
    let mut tickets = Vec::new();
    for _ in 0..16 {
        let ticket = session.submit(br#"{"op":"identity"}"#);
        assert_ne!(ticket, 0);
        tickets.push(ticket);
    }
    assert_eq!(session.submit(b"{}"), 0);
    for ticket in tickets {
        assert_eq!(gcoms_mobile_cancel(session.0, ticket), 0);
    }
}

#[cfg(all(feature = "relay", feature = "fixtures"))]
#[test]
fn profile_channel_file_and_suspend_reopen_through_abi() {
    let directory = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(directory.path(), true).unwrap();
    let session = Session::new();
    let open = json!({"op":"open", "config": {
        "application":"mobile-smoke", "profile":directory.path().join("profile"),
        "secret":"fixture-unlock", "fixture":true
    }});
    let identity = session.request(open.clone())["ok"].clone();
    assert!(identity["safety_number"].is_string(), "{identity}");
    let channel = session.request(json!({"op":"create_channel","channel":"mobile","display":"owner","capacity":8,"visibility":"Private"}));
    let channel = channel.get("ok").expect("channel").clone();
    let invitation =
        session.request(json!({"op":"create_invitation","channel":"mobile","lifetime_secs":3600}));
    assert!(invitation["ok"]["link"].is_string(), "{invitation}");
    let id: Vec<u8> = (1..=16).collect();
    let scope = json!({"channel":channel,"participants":[]});
    let prepare = json!({"op":"files","request":{"Prepare":{"id":id,"scope":scope,"name":"mobile.txt","size_bytes":3}}});
    assert!(session.request(prepare).get("ok").is_some());
    assert!(session
        .request(
            json!({"op":"files","request":{"WritePiece":{"id":id,"piece":0,"bytes":[65,66,67]}}})
        )
        .get("ok")
        .is_some());
    assert!(session
        .request(json!({"op":"files","request":{"Commit":{"id":id}}}))
        .get("ok")
        .is_some());
    assert!(session.request(json!({"op":"suspend"})).get("ok").is_some());
    assert!(session
        .request(json!({"op":"identity"}))
        .get("error")
        .is_some());
    let reopened = session.request(open);
    assert_eq!(reopened["ok"]["safety_number"], identity["safety_number"]);
    let piece = session.request(json!({"op":"files","request":{"ReadPiece":{"id":id,"piece":0}}}));
    assert_eq!(piece["ok"]["Piece"], json!([65, 66, 67]));
    assert!(session.request(json!({"op":"suspend"})).get("ok").is_some());
}
