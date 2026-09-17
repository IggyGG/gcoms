#[gcoms_rpc::service(name = "example.bad", version = 1)]
trait Bad {
    #[rpc(id = "read", kind = "query")]
    async fn read(&self) -> Result<u64, String>;
}
fn main() {}
