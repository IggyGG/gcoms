//! This contract intentionally uses a Cargo dependency alias.
#[comms::service(name = "example.alias", version = 1)]
pub trait Echo {
    #[rpc(id = "echo", kind = "query")]
    async fn echo(&self, text: String) -> Result<String, String>;
    #[rpc(id = "remember", kind = "operation")]
    async fn remember(&self, text: String) -> Result<String, String>;
}

pub struct EchoHost;
#[comms::async_trait]
impl Echo for EchoHost {
    async fn echo(&self, text: String) -> Result<String, String> {
        Ok(text)
    }
    async fn remember(&self, text: String) -> Result<String, String> {
        Ok(text)
    }
}
