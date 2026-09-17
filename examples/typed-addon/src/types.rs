fn main() {
    use gcoms_rpc::ts_rs::TS;
    println!(
        "{}",
        gcoms_rpc::serde_json::to_string_pretty(&gcoms_rpc::serde_json::json!({
            "service": gcoms_addon_example::GreetingServiceContract::descriptor(),
            "typescript": format!("export {}\n", gcoms_addon_example::Greeting::decl()),
        }))
        .expect("example schemas")
    );
}
