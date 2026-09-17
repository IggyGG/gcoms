#[gcoms_rpc::service(name = "example.bad", version = 1)]
trait Bad {
    #[rpc(id = "read")]
    async fn read(&self) -> Result<String, String>;
}
fn main() {}
