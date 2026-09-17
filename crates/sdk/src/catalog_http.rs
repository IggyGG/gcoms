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
    pub(crate) fn validate_size(&self) -> Result<(), crate::SdkError> {
        if self.method.len() > 8 || self.url.len() > 4096 || self.body.len() > 128 * 1024 {
            return Err(crate::SdkError::Protocol(
                "catalog request exceeds limit".into(),
            ));
        }
        Ok(())
    }
}
