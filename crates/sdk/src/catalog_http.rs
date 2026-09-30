//! Scoped backend catalog access. No caller-controlled sockets, DNS or headers.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogHttpRequest {
    pub method: String,
    pub url: String,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogHttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl CatalogHttpRequest {
    pub(crate) fn is_hosted(&self) -> bool {
        self.method == "POST"
            && (self.url.ends_with("/v1/hosted") || self.url.ends_with("/v1/hosted/bulk"))
    }

    pub(crate) fn validate_size(&self) -> Result<(), crate::SdkError> {
        let limit = if self.is_hosted() {
            crate::hosted::MAX_HTTP_BYTES
        } else {
            128 * 1024
        };
        if self.method.len() > 8 || self.url.len() > 4096 || self.body.len() > limit {
            return Err(crate::SdkError::Protocol(
                "catalog request exceeds limit".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{Capability, Request};
    #[test]
    fn hosted_capability_and_larger_body_are_scoped_to_ipc26() {
        for suffix in ["/v1/hosted", "/v1/hosted/bulk"] {
            let request = CatalogHttpRequest {
                method: "POST".into(),
                url: format!("https://catalog.example{suffix}"),
                body: vec![0; 2 * 1024 * 1024],
            };
            request.validate_size().unwrap();
            let request = Request::CatalogHttp(request);
            assert_eq!(request.minimum_version(), 26);
            assert_eq!(request.required_capability(), Capability::HostedChannels);
        }
        let old = CatalogHttpRequest {
            method: "PUT".into(),
            url: "https://catalog.example/v1/descriptors".into(),
            body: vec![0; 128 * 1024 + 1],
        };
        assert!(old.validate_size().is_err());
        let old = Request::CatalogHttp(old);
        assert_eq!(old.minimum_version(), 15);
        assert_eq!(old.required_capability(), Capability::CatalogAccess);
    }
}
