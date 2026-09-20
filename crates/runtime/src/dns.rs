//! Name resolution for the HTTPS clients (bootstrap, catalogs).
//!
//! A fully static musl binary has no libc resolver worth the name: musl's
//! `getaddrinfo` reads `/etc/resolv.conf`, which does not exist on Android,
//! so every hostname lookup fails inside Termux even though the network is
//! fine. Relay traffic is unaffected (relay cards carry IP addresses), but
//! the very first step, the HTTPS bootstrap, needs a hostname.
//!
//! This resolver tries the system resolver first and, when that fails,
//! sends a plain DNS query itself to nameservers found in `$PREFIX/etc/resolv.conf`
//! (Termux ships one) or `GC_DNS_SERVERS`, falling back to well-known public
//! resolvers. Answers are used only to open a TLS connection that still
//! verifies the certificate for the requested hostname, so a wrong answer
//! cannot redirect a client to an impostor.

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
const PUBLIC_RESOLVERS: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
];

/// System resolver with a UDP fallback for static builds.
#[derive(Debug, Default)]
pub struct FallbackResolver;

impl Resolve for FallbackResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            // Literal addresses never need a lookup.
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Ok(Box::new(std::iter::once(SocketAddr::new(ip, 0))) as Addrs);
            }
            let system = tokio::net::lookup_host((host.as_str(), 0)).await;
            if let Ok(addrs) = system {
                let addrs: Vec<SocketAddr> = addrs.collect();
                if !addrs.is_empty() {
                    return Ok(Box::new(addrs.into_iter()) as Addrs);
                }
            }
            let addrs = udp_lookup(&host).await.map_err(|error| {
                Box::new(std::io::Error::other(format!("resolve {host}: {error}")))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// Nameservers to try, in order: `GC_DNS_SERVERS` (comma separated), then
/// any `nameserver` lines from a resolv.conf we can find, then public ones.
fn nameservers() -> Vec<IpAddr> {
    let mut servers = Vec::new();
    if let Ok(configured) = std::env::var("GC_DNS_SERVERS") {
        servers.extend(
            configured
                .split(',')
                .filter_map(|value| value.trim().parse::<IpAddr>().ok()),
        );
    }
    let mut files = vec![std::path::PathBuf::from("/etc/resolv.conf")];
    if let Ok(prefix) = std::env::var("PREFIX") {
        files.push(std::path::Path::new(&prefix).join("etc/resolv.conf"));
    }
    for file in files {
        if let Ok(text) = std::fs::read_to_string(file) {
            for line in text.lines() {
                let mut words = line.split_whitespace();
                if words.next() == Some("nameserver") {
                    if let Some(ip) = words.next().and_then(|value| value.parse::<IpAddr>().ok()) {
                        servers.push(ip);
                    }
                }
            }
        }
    }
    servers.extend(PUBLIC_RESOLVERS);
    servers.dedup();
    servers
}

/// One A query per nameserver until one answers with addresses.
async fn udp_lookup(host: &str) -> Result<Vec<SocketAddr>, String> {
    let query = build_query(host)?;
    let mut last = String::from("no nameserver answered");
    for server in nameservers() {
        match query_server(server, &query).await {
            Ok(addrs) if !addrs.is_empty() => {
                return Ok(addrs.into_iter().map(|ip| SocketAddr::new(ip, 0)).collect());
            }
            Ok(_) => last = format!("{server}: no A records"),
            Err(error) => last = format!("{server}: {error}"),
        }
    }
    Err(last)
}

async fn query_server(server: IpAddr, query: &[u8]) -> Result<Vec<IpAddr>, String> {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().expect("static")
    } else {
        "[::]:0".parse().expect("static")
    };
    let socket = tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(|error| error.to_string())?;
    socket
        .send_to(query, SocketAddr::new(server, 53))
        .await
        .map_err(|error| error.to_string())?;
    let mut buffer = [0u8; 512];
    let (length, _) = tokio::time::timeout(QUERY_TIMEOUT, socket.recv_from(&mut buffer))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|error| error.to_string())?;
    parse_answers(&buffer[..length], &query[..2])
}

/// A minimal recursive A query with a random id.
fn build_query(host: &str) -> Result<Vec<u8>, String> {
    let id: [u8; 2] = rand::random();
    let mut packet = vec![id[0], id[1], 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in host.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return Err(format!("invalid hostname label in {host}"));
        }
        packet.push(bytes.len() as u8);
        packet.extend_from_slice(bytes);
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    Ok(packet)
}

/// Extract A records from a response whose id matches `expected_id`.
fn parse_answers(packet: &[u8], expected_id: &[u8]) -> Result<Vec<IpAddr>, String> {
    if packet.len() < 12 || &packet[..2] != expected_id {
        return Err("malformed or mismatched DNS reply".into());
    }
    if packet[3] & 0x0f != 0 {
        return Err(format!("DNS rcode {}", packet[3] & 0x0f));
    }
    let questions = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let answers = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_name(packet, offset)?;
        offset += 4;
    }
    let mut ips = Vec::new();
    for _ in 0..answers {
        offset = skip_name(packet, offset)?;
        if offset + 10 > packet.len() {
            return Err("truncated DNS answer".into());
        }
        let record_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let length = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        if offset + length > packet.len() {
            return Err("truncated DNS record".into());
        }
        if record_type == 1 && length == 4 {
            ips.push(IpAddr::V4(Ipv4Addr::new(
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            )));
        }
        offset += length;
    }
    Ok(ips)
}

fn skip_name(packet: &[u8], mut offset: usize) -> Result<usize, String> {
    loop {
        let Some(&length) = packet.get(offset) else {
            return Err("truncated DNS name".into());
        };
        if length == 0 {
            return Ok(offset + 1);
        }
        if length & 0xc0 == 0xc0 {
            return Ok(offset + 2);
        }
        offset += 1 + usize::from(length);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_and_answer_roundtrip() {
        let query = build_query("gc.triform.dev").unwrap();
        assert_eq!(&query[2..4], &[0x01, 0x00]);
        assert!(query.ends_with(&[0, 0, 1, 0, 1]));
        // Hand-built reply: same id, one question, one A record via pointer.
        let mut reply = query.clone();
        reply[2] = 0x81;
        reply[3] = 0x80;
        reply[7] = 1;
        reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 95, 217, 169, 216]);
        let ips = parse_answers(&reply, &query[..2]).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(95, 217, 169, 216))]);
        assert!(parse_answers(&reply, &[0, 0]).is_err());
        let mut nx = reply.clone();
        nx[3] = 0x83;
        assert!(parse_answers(&nx, &query[..2])
            .unwrap_err()
            .contains("rcode 3"));
    }

    #[test]
    fn nameserver_list_ends_with_public_resolvers() {
        let servers = nameservers();
        assert!(servers.contains(&PUBLIC_RESOLVERS[0]));
        assert!(servers.contains(&PUBLIC_RESOLVERS[1]));
    }

    #[tokio::test]
    async fn literal_addresses_skip_lookup() {
        let name: Name = "203.0.113.5".parse().unwrap();
        let addrs: Vec<SocketAddr> = FallbackResolver.resolve(name).await.unwrap().collect();
        assert_eq!(addrs, vec!["203.0.113.5:0".parse().unwrap()]);
    }
}
