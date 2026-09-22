//! A complete application route has one entry, three middles and a terminal.
//! Validate the whole route before opening any stream, including nonadjacent
//! relays: different ports or certificates do not make a repeated IP independent.
use super::{directory::Introduction, transit::TransitDescriptor};
use crate::{wire::Target, Result};
use std::net::SocketAddr;

pub const MIDDLE_HOPS: usize = 3;
pub const RELAY_HOPS: usize = MIDDLE_HOPS + 2;
pub type MiddlePath = [TransitDescriptor; MIDDLE_HOPS];
pub(crate) type Service = (SocketAddr, [u8; 32]);

fn conflicts(a: Service, b: Service) -> bool {
    a.0.ip() == b.0.ip() || a.1 == b.1
}

pub(crate) fn validate(
    entry: Service,
    middles: &MiddlePath,
    target: &Target,
    excluded: &[Service],
) -> Result<()> {
    if excluded.len() > 64 {
        return Err("too many GC/2 route exclusions".into());
    }
    Target::decode(&target.encode())?;
    let mut preceding = [entry; MIDDLE_HOPS + 1];
    for (index, middle) in middles.iter().enumerate() {
        middle.validate()?;
        let service = (middle.addr, middle.service_id);
        if preceding[..=index]
            .iter()
            .any(|other| conflicts(service, *other))
        {
            return Err("GC/2 route repeats a relay identity or IP".into());
        }
        preceding[index + 1] = service;
    }
    for service in preceding {
        if excluded.iter().any(|other| conflicts(service, *other))
            || matches!(target, Target::Relay { addr, service_id }
                if conflicts(service, (*addr, *service_id)))
        {
            return Err("GC/2 route conflicts with an endpoint or exclusion".into());
        }
    }
    Ok(())
}

/// The directory has already excluded the terminal, local services and stale
/// advertisements. Find a complete path without allowing a short-path fallback.
/// Backtracking also handles candidate sets with overlapping addresses/pins.
pub(crate) fn select(
    available: &[Introduction],
    entry: Service,
    now: u64,
) -> Result<Option<MiddlePath>> {
    for (a_index, a) in available.iter().enumerate() {
        if a.conflicts(entry.0, entry.1) {
            continue;
        }
        for (b_index, b) in available.iter().enumerate().skip(a_index + 1) {
            if b.conflicts(entry.0, entry.1) || b.conflicts(a.addr, a.service_id) {
                continue;
            }
            for c in available.iter().skip(b_index + 1) {
                if !c.conflicts(entry.0, entry.1)
                    && !c.conflicts(a.addr, a.service_id)
                    && !c.conflicts(b.addr, b.service_id)
                {
                    return Ok(Some([a.transit(now)?, b.transit(now)?, c.transit(now)?]));
                }
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn introduction(host: u8, pin: u8) -> Introduction {
        Introduction {
            addr: format!("127.0.0.{host}:443").parse().unwrap(),
            service_id: [pin; 32],
            reentry_cap: [100; 32],
            entry_cap: [101; 32],
            transit_cap: [102; 32],
            expires_at: crate::route::now_unix() + 3600,
        }
    }

    #[test]
    fn selection_never_falls_back_to_fewer_than_three_middles() {
        let entry = introduction(1, 1);
        let candidates: Vec<_> = (2..=4).map(|id| introduction(id, id)).collect();
        for length in 0..MIDDLE_HOPS {
            assert!(select(
                &candidates[..length],
                (entry.addr, entry.service_id),
                crate::route::now_unix(),
            )
            .unwrap()
            .is_none());
        }
        assert!(select(
            &candidates,
            (entry.addr, entry.service_id),
            crate::route::now_unix(),
        )
        .unwrap()
        .is_some());
        assert_eq!(RELAY_HOPS, 5);
    }

    #[test]
    fn selection_backtracks_around_overlapping_addresses_and_pins() {
        let entry = introduction(1, 1);
        // Choosing the first candidate greedily would leave only two middles.
        let candidates = [
            introduction(2, 2),
            introduction(3, 2),
            introduction(2, 3),
            introduction(4, 4),
        ];
        let selected = select(
            &candidates,
            (entry.addr, entry.service_id),
            crate::route::now_unix(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            selected.each_ref().map(|r| (r.addr, r.service_id)),
            [
                (candidates[1].addr, candidates[1].service_id),
                (candidates[2].addr, candidates[2].service_id),
                (candidates[3].addr, candidates[3].service_id),
            ]
        );
    }

    #[test]
    fn every_position_checks_endpoint_exclusions_and_nonadjacent_reuse() {
        let entry = introduction(1, 1);
        let entry = (entry.addr, entry.service_id);
        let middles = [2, 3, 4].map(|id| {
            introduction(id, id)
                .transit(crate::route::now_unix())
                .unwrap()
        });
        let terminal = introduction(5, 5);
        let target = Target::Relay {
            addr: terminal.addr,
            service_id: terminal.service_id,
        };
        validate(entry, &middles, &target, &[]).unwrap();
        for index in 0..MIDDLE_HOPS {
            assert!(validate(
                entry,
                &middles,
                &target,
                &[(middles[index].addr, [90; 32]),]
            )
            .is_err());
            assert!(validate(
                entry,
                &middles,
                &target,
                &[("127.0.0.99:443".parse().unwrap(), middles[index].service_id),]
            )
            .is_err());
            for duplicate in [entry, (terminal.addr, terminal.service_id)] {
                let mut invalid = middles.clone();
                invalid[index].addr = duplicate.0;
                assert!(validate(entry, &invalid, &target, &[]).is_err());
                invalid[index] = middles[index].clone();
                invalid[index].service_id = duplicate.1;
                assert!(validate(entry, &invalid, &target, &[]).is_err());
            }
            let mut expired = middles.clone();
            expired[index].expires_at = crate::route::now_unix();
            assert!(validate(entry, &expired, &target, &[]).is_err());
        }
        for a in 0..MIDDLE_HOPS {
            for b in (a + 1)..MIDDLE_HOPS {
                let mut invalid = middles.clone();
                invalid[b].addr = invalid[a].addr;
                assert!(validate(entry, &invalid, &target, &[]).is_err());
                invalid[b] = middles[b].clone();
                invalid[b].service_id = invalid[a].service_id;
                assert!(validate(entry, &invalid, &target, &[]).is_err());
            }
        }
    }
}
