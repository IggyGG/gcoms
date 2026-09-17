//! Carrier v1 is separate from GC application cells. All records are 4096 bytes.
use crate::Result;
use rand::RngCore;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const RECORD_SIZE: usize = 4096;
pub const HEADER_SIZE: usize = 8;
pub const MAX_DATA: usize = RECORD_SIZE - HEADER_SIZE;
const MAGIC: &[u8; 4] = b"GCT1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Open = 1,
    Opened = 2,
    Data = 3,
    Close = 4,
    Cover = 5,
    Introduce = 6,
    Introductions = 7,
    Provision = 8,
    Provisioned = 9,
    Advertise = 10,
    Advertised = 11,
}

pub struct Record {
    pub kind: Kind,
    pub payload: Vec<u8>,
}

impl Record {
    pub fn encode(kind: Kind, payload: &[u8]) -> Result<[u8; RECORD_SIZE]> {
        if payload.len() > MAX_DATA {
            return Err("carrier payload exceeds record bound".into());
        }
        let mut out = [0; RECORD_SIZE];
        rand::thread_rng().fill_bytes(&mut out);
        out[..4].copy_from_slice(MAGIC);
        out[4] = kind as u8;
        out[5] = 0;
        out[6..8].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        out[8..8 + payload.len()].copy_from_slice(payload);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != RECORD_SIZE || &bytes[..4] != MAGIC || bytes[5] != 0 {
            return Err("invalid carrier record".into());
        }
        let len = u16::from_be_bytes(bytes[6..8].try_into()?) as usize;
        if len > MAX_DATA {
            return Err("invalid carrier length".into());
        }
        let kind = match bytes[4] {
            1 => Kind::Open,
            2 => Kind::Opened,
            3 => Kind::Data,
            4 => Kind::Close,
            5 => Kind::Cover,
            6 => Kind::Introduce,
            7 => Kind::Introductions,
            8 => Kind::Provision,
            9 => Kind::Provisioned,
            10 => Kind::Advertise,
            11 => Kind::Advertised,
            _ => return Err("unsupported carrier operation".into()),
        };
        if matches!(kind, Kind::Close | Kind::Cover) && len != 0 {
            return Err("control record has payload".into());
        }
        if kind == Kind::Data && len == 0 {
            return Err("empty data record".into());
        }
        Ok(Self {
            kind,
            payload: bytes[8..8 + len].to_vec(),
        })
    }
}

/// The pin identifies the next relay; the originating endpoint authenticates it
/// inside this stream. A relay must never substitute its own TLS termination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Relay {
        addr: SocketAddr,
        service_id: [u8; 32],
    },
    /// Only explicitly configured catalog origins may use remote DNS/HTTPS egress.
    Https { host: String, port: u16 },
}

impl Target {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Relay { addr, service_id } => {
                out.push(1);
                out.extend_from_slice(&encode_address(*addr));
                out.extend_from_slice(service_id);
            }
            Self::Https { host, port } => {
                out.push(2);
                out.extend_from_slice(&port.to_be_bytes());
                out.extend_from_slice(host.as_bytes());
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        match bytes.first() {
            Some(1) if bytes.len() == 52 => {
                let addr = decode_address(&bytes[1..20])?;
                let service_id = bytes[20..].try_into()?;
                if service_id == [0; 32] {
                    return Err("missing relay pin".into());
                }
                Ok(Self::Relay { addr, service_id })
            }
            Some(2) if (4..=256).contains(&bytes.len()) => {
                let port = u16::from_be_bytes(bytes[1..3].try_into()?);
                let host = std::str::from_utf8(&bytes[3..])?;
                if port != 443 || !valid_host(host) {
                    return Err("invalid HTTPS origin".into());
                }
                Ok(Self::Https {
                    host: host.into(),
                    port,
                })
            }
            _ => Err("invalid carrier target".into()),
        }
    }
}

pub fn valid_host(host: &str) -> bool {
    host.len() <= 253
        && host.contains('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
        && host.parse::<IpAddr>().is_err()
}

pub fn encode_address(addr: SocketAddr) -> [u8; 19] {
    let mut out = [0; 19];
    match addr.ip() {
        IpAddr::V4(ip) => {
            out[0] = 4;
            out[1..5].copy_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out[0] = 6;
            out[1..17].copy_from_slice(&ip.octets());
        }
    }
    out[17..].copy_from_slice(&addr.port().to_be_bytes());
    out
}

pub fn decode_address(bytes: &[u8]) -> Result<SocketAddr> {
    if bytes.len() != 19 {
        return Err("invalid relay address".into());
    }
    let ip = match bytes[0] {
        4 if bytes[5..17] == [0; 12] => {
            IpAddr::V4(Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4]))
        }
        6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[1..17])?)),
        _ => return Err("noncanonical relay address".into()),
    };
    let port = u16::from_be_bytes(bytes[17..].try_into()?);
    if port == 0
        || ip.is_unspecified()
        || ip.is_multicast()
        || matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some())
    {
        return Err("unusable relay address".into());
    }
    Ok(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_vectors_and_strict_decoding() {
        let target = Target::Relay {
            addr: "192.0.2.7:443".parse().unwrap(),
            service_id: [0x21; 32],
        };
        let encoded = target.encode();
        assert_eq!(&encoded[..6], &[1, 4, 192, 0, 2, 7]);
        assert_eq!(&encoded[18..20], &[1, 187]);
        assert_eq!(Target::decode(&encoded).unwrap(), target);
        let mut bad = encoded.clone();
        bad[6] = 1;
        assert!(Target::decode(&bad).is_err());
        for len in 0..encoded.len() {
            assert!(Target::decode(&encoded[..len]).is_err());
        }
        assert!(Target::decode(&[encoded, vec![0]].concat()).is_err());
        for host in [
            "user@example.com",
            "example.com/",
            "example.com.",
            "127.0.0.1",
            "-a.com",
        ] {
            assert!(!valid_host(host));
        }
    }

    #[test]
    fn record_bounds_and_control_validation() {
        let bytes = Record::encode(Kind::Data, &vec![42; MAX_DATA]).unwrap();
        assert_eq!(Record::decode(&bytes).unwrap().payload, vec![42; MAX_DATA]);
        assert!(Record::encode(Kind::Data, &vec![0; MAX_DATA + 1]).is_err());
        let mut invalid = bytes;
        invalid[4] = Kind::Cover as u8;
        assert!(Record::decode(&invalid).is_err());
        invalid[4] = Kind::Data as u8;
        invalid[5] = 1;
        assert!(Record::decode(&invalid).is_err());
        for len in [0, 1, HEADER_SIZE, RECORD_SIZE - 1] {
            assert!(Record::decode(&bytes[..len]).is_err());
        }
    }
}
