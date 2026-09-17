#[gcoms_rpc::service(name = "example.bad", version = 1)]
trait Bad {
    #[rpc(id = "read", kind = "query")]
    async fn read(&self) -> Result<String, String>;
    #[rpc(id = "read", kind = "query")]
    async fn other(&self) -> Result<String, String>;
}
fn main() {}
