#[gcoms_rpc::service(name = "example.bad", version = 1)]
trait Bad {
    #[rpc(id = "read", kind = "query")]
    async fn read(&self, text: &str) -> Result<String, String>;
}
fn main() {}
