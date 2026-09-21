use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The app operator configures this destination. Queue owners cannot supply URLs.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    pub url: String,
    pub relay_id: String,
    pub key: [u8; 32],
}
impl Drop for GatewayConfig {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}
impl GatewayConfig {
    pub(crate) fn client(&self) -> Result<reqwest::Client, String> {
        let url = url::Url::parse(&self.url).map_err(|_| "invalid push gateway URL")?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/v1/events"
            || self.relay_id.is_empty()
            || self.relay_id.len() > 128
            || !self
                .relay_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || self.key == [0; 32]
        {
            return Err("invalid push gateway configuration".into());
        }
        reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| e.to_string())
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) async fn worker(
    config: GatewayConfig,
    client: reqwest::Client,
    mut events: tokio::sync::mpsc::Receiver<[u8; 32]>,
) {
    while let Some(reference) = events.recv().await {
        // Stable nonce across retries makes a lost HTTP response idempotent.
        let nonce = hex(&rand::random::<[u8; 16]>());
        let body = format!(
            r#"{{"activity":"message","reference":"{}"}}"#,
            hex(&reference)
        );
        for attempt in 0..3 {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_string();
            let mut mac = Hmac::<Sha256>::new_from_slice(&config.key).expect("fixed length");
            mac.update(b"GCOMS-PUSH-EVENT-v1\0");
            mac.update(timestamp.as_bytes());
            mac.update(b"\n");
            mac.update(nonce.as_bytes());
            mac.update(b"\n");
            mac.update(body.as_bytes());
            let result = client
                .post(&config.url)
                .header("content-type", "application/json")
                .header("x-relay-id", &config.relay_id)
                .header("x-timestamp", &timestamp)
                .header("x-nonce", &nonce)
                .header("x-signature", hex(&mac.finalize().into_bytes()))
                .body(body.clone())
                .send()
                .await;
            match result {
                Ok(reply) if reply.status().is_success() => break,
                Ok(reply) if reply.status().is_client_error() && reply.status().as_u16() != 429 => {
                    break
                }
                _ if attempt < 2 => tokio::time::sleep(Duration::from_secs(2u64 << attempt)).await,
                _ => {}
            }
        }
    }
}
