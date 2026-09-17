use gcoms_core::{decode, Cell, CellType};
use gcoms_crypto::session::{FirstMove, Frame};
use gcoms_crypto::{Bundle, IdentityKeypair};
use gcoms_mls::{Caps, ChannelMember, OwnerSession};
use gcoms_node::alias::ForwardGrant;
use gcoms_node::channel::{decode_inner, decode_pex, encode_pex, PeerRef};
use gcoms_node::relay::{RelayPush, RelayTarget, UnauthenticatedRelayPush};
use rand::rngs::StdRng;
use rand::RngCore;
use rand::SeedableRng;
use std::time::Instant;

pub struct TargetStats {
    pub target: &'static str,
    pub execs: u64,
    pub accepted: u64,
    pub elapsed: std::time::Duration,
}

fn mutate(rng: &mut StdRng, seed: &[u8], out: &mut Vec<u8>) {
    out.clear();
    match rng.next_u32() % 4 {
        0 => {
            let len = (rng.next_u32() % 20000) as usize;
            out.resize(len, 0);
            rng.fill_bytes(out);
        }
        1 => {
            out.extend_from_slice(seed);
            let flips = (rng.next_u32() % 16) + 1;
            for _ in 0..flips {
                if out.is_empty() {
                    break;
                }
                let pos = (rng.next_u32() as usize) % out.len();
                out[pos] ^= (rng.next_u32() % 255 + 1) as u8;
            }
        }
        2 => {
            let cut = if seed.is_empty() {
                0
            } else {
                (rng.next_u32() as usize) % (seed.len() + 1)
            };
            out.extend_from_slice(&seed[..cut]);
        }
        _ => {
            out.extend_from_slice(seed);
            let extra = (rng.next_u32() % 64) as usize;
            let mut tail = vec![0u8; extra];
            rng.fill_bytes(&mut tail);
            out.extend_from_slice(&tail);
        }
    }
}

pub fn fuzz_target(target: &str, iters: u64, seed: u64) -> TargetStats {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut execs: u64 = 0;
    let mut accepted: u64 = 0;
    let mut buf = Vec::new();
    let started = Instant::now();

    match target {
        "cell" => {
            let valid = Cell::new(CellType::Msg, 0, 1, (0..100).map(|i| i as u8).collect())
                .encode_wire()
                .unwrap();
            for _ in 0..iters {
                mutate(&mut rng, &valid, &mut buf);
                execs += 1;
                if decode(&buf).is_ok() {
                    accepted += 1;
                }
            }
        }
        "frame" => {
            let bob = IdentityKeypair::from_seed([0xB2; 32]);
            let (bundle, secrets) = bob.issue_bundle();
            let (fm, mut alice) =
                gcoms_crypto::initiate(&bob.public_bytes(), &bundle, b"seed").unwrap();
            let (_p, _b) = secrets.accept(&fm).unwrap();
            let valid = alice.send(b"x").unwrap().encode();
            for _ in 0..iters {
                mutate(&mut rng, &valid, &mut buf);
                execs += 1;
                if Frame::decode(&buf).is_some() {
                    accepted += 1;
                }
            }
        }
        "receive" => {
            let bob = IdentityKeypair::from_seed([0xB2; 32]);
            let (bundle, secrets) = bob.issue_bundle();
            let (fm, mut alice) =
                gcoms_crypto::initiate(&bob.public_bytes(), &bundle, b"seed").unwrap();
            let (_p, mut bob_session) = secrets.accept(&fm).unwrap();
            let valid = alice.send(b"x").unwrap();
            let mut round = 0u64;
            for _ in 0..iters {
                mutate(&mut rng, &valid.encode(), &mut buf);
                round += 1;
                if round.is_multiple_of(4) {
                    if let Ok(f) = alice.send(b"keepalive") {
                        let _ = bob_session.receive(&f);
                    }
                }
                execs += 1;
                if let Some(f) = Frame::decode(&buf) {
                    if bob_session.receive(&f).is_ok() {
                        accepted += 1;
                    }
                }
            }
        }
        "firstmove" => {
            let bob = IdentityKeypair::from_seed([0xB2; 32]);
            let (bundle, secrets) = bob.issue_bundle();
            let (fm, _alice) =
                gcoms_crypto::initiate(&bob.public_bytes(), &bundle, b"seed").unwrap();
            let valid = fm.encode();
            for _ in 0..iters {
                mutate(&mut rng, &valid, &mut buf);
                execs += 1;
                if let Some(fm) = FirstMove::decode(&buf) {
                    if secrets.accept(&fm).is_ok() {
                        accepted += 1;
                    }
                }
            }
        }
        "invite" => {
            let owner = OwnerSession::create(IdentityKeypair::from_seed([0x5A; 32]), "founder", 64)
                .unwrap();
            let prepared = ChannelMember::prepare("fuzz").unwrap();
            let valid = owner
                .sign_invite_key_package(
                    &gcoms_mls::ChannelMember::key_package_bytes(&prepared).unwrap_or_default(),
                    "fuzz",
                    Caps::member(),
                    3600,
                )
                .encode();
            for _ in 0..iters {
                mutate(&mut rng, &valid, &mut buf);
                execs += 1;
                if gcoms_mls::Invite::decode(&buf).is_some() {
                    accepted += 1;
                }
            }
        }
        "bundle" => {
            let bob = IdentityKeypair::from_seed([0xB2; 32]);
            let (bundle, _secrets) = bob.issue_bundle();
            let valid = bundle.encode();
            for _ in 0..iters {
                mutate(&mut rng, &valid, &mut buf);
                execs += 1;
                if Bundle::decode(&buf).is_some() {
                    accepted += 1;
                }
            }
        }
        "control" => {
            const CORPUS: &[&[u8]] = &[
                br#"{"id":1,"cmd":"status"}"#,
                br#"{"cmd":null,"id":{"nested":[true,false,null]}}"#,
                br#"{"cmd":"status","cmd":"node_info"}"#,
                br#"{"cmd":"send_1to1","peer_info_b64":"%%%","text_b64":"AA"}"#,
                br#"{"id":18446744073709551616,"cmd":"key_package"}"#,
                br#"{"cmd":"\u0000\ud83d\ude80","extra":"\\\"\n\t"}"#,
                br#"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["#,
                b"{\"cmd\":\"status\"}\xff",
            ];
            for _ in 0..iters {
                let seed = CORPUS[(rng.next_u32() as usize) % CORPUS.len()];
                mutate(&mut rng, seed, &mut buf);
                execs += 1;
                if gcoms_node::control::parse_request(&buf).is_ok() {
                    accepted += 1;
                }
            }
        }
        // Parsers touched by the 2026-09-05 hardening pass. Each seed is a
        // valid canonical encoding; the mutator does the rest.
        "relay" => {
            // A cover RELAY_PUSH (msg_len = 0): the exact shape the relay
            // must accept, record, and not enqueue. push_payload parsing is
            // the pre-auth attack surface.
            let cell = RelayPush::cover([9; 32], 0x0102_0304, [7; 16], u64::MAX / 2)
                .encode_into_cell(&[0x11; 32], &[0x22; 32])
                .unwrap();
            let valid = cell.encode_wire().unwrap();
            for _ in 0..iters {
                mutate(&mut rng, &valid, &mut buf);
                execs += 1;
                if let Ok(cell) = decode(&buf) {
                    if UnauthenticatedRelayPush::parse(cell).is_ok() {
                        accepted += 1;
                    }
                }
            }
        }
        "archive" => {
            // Forward-grant bearer decode (v9 sealed-archive payloads and
            // DirectRecord::ForwardGrant both funnel through this).
            let target = RelayTarget {
                address: "203.0.113.7:8443".parse().unwrap(),
                relay_service_id: [0x33; 32],
            };
            let grant = ForwardGrant {
                target,
                frwd_path: "fuzz-inbox".into(),
                hop_key: [5; 32],
                expires_at: u64::MAX / 2,
                issued_by: vec![0xAB; 48],
            };
            let valid = grant.encode();
            for _ in 0..iters {
                mutate(&mut rng, &valid, &mut buf);
                execs += 1;
                if ForwardGrant::decode(&buf).is_some() {
                    accepted += 1;
                }
            }
        }
        "chan" => {
            // Channel inner records and PEX cells, alternating per exec so one
            // target exercises both overlay parsers.
            let mut inner = vec![0x01u8];
            inner.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
            inner.extend_from_slice(b"hello channel");
            let pex_refs: Vec<PeerRef> = Vec::new();
            let pex = encode_pex("fuzz", &pex_refs, &[[1; 16], [2; 16]]);
            for _ in 0..iters {
                let seed: &[u8] = if execs.is_multiple_of(2) {
                    &inner
                } else {
                    &pex
                };
                mutate(&mut rng, seed, &mut buf);
                execs += 1;
                let ok = if execs.is_multiple_of(2) {
                    decode_inner(&buf).is_some()
                } else {
                    decode_pex(&buf).is_some()
                };
                if ok {
                    accepted += 1;
                }
            }
        }
        _ => panic!("unknown target {target}"),
    }
    TargetStats {
        target: match target {
            "cell" => "cell",
            "frame" => "frame",
            "receive" => "receive",
            "firstmove" => "firstmove",
            "invite" => "invite",
            "control" => "control",
            "relay" => "relay",
            "archive" => "archive",
            "chan" => "chan",
            _ => "bundle",
        },
        execs,
        accepted,
        elapsed: started.elapsed(),
    }
}

pub const TARGETS: [&str; 10] = [
    "cell",
    "frame",
    "receive",
    "firstmove",
    "invite",
    "bundle",
    "control",
    "relay",
    "archive",
    "chan",
];

pub fn fuzz_all(iters: u64) -> Vec<TargetStats> {
    TARGETS
        .iter()
        .enumerate()
        .map(|(i, t)| fuzz_target(t, iters, 0xF00D + i as u64))
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn short_swarm_no_crashes() {
        let results = super::fuzz_all(20_000);
        assert_eq!(results.len(), 10);
        for r in &results {
            assert!(r.execs == 20_000);
        }
    }

    #[test]
    fn control_target_exercises_parser_without_network() {
        let result = super::fuzz_target("control", 10_000, 0x0C01_7201);
        assert_eq!(result.target, "control");
        assert_eq!(result.execs, 10_000);
        assert!(result.accepted < result.execs);
    }
}
