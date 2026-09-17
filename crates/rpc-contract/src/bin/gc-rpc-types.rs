fn main() {
    use gcoms_rpc_contract::*;
    let operation = OperationToken {
        id: OperationId::new("fixture-operation-01").unwrap(),
        deadline: DecimalU64(u64::MAX),
    };
    let request = Request {
        rpc: WIRE_VERSION,
        id: OperationId::new("fixture-request-01").unwrap(),
        instance: "fixture-instance".into(),
        service: "example.greeting".into(),
        version: 1,
        method: "uppercase".into(),
        invocation: Invocation::Call {
            args: serde_json::json!({"text": "  λ\ntext  "}),
            operation: Some(operation.clone()),
        },
    };
    let reply = request.reply(ReplyBody::Done {
        outcome: Outcome::Ok(serde_json::json!({"text": "  Λ\nTEXT  "})),
    });
    let handle = OperationHandle {
        destination: "/rpc".into(),
        instance: request.instance.clone(),
        service: request.service.clone(),
        version: request.version,
        method: request.method.clone(),
        operation,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "typescript": gcoms_rpc_contract::typescript(),
            "request": schemars::schema_for!(gcoms_rpc_contract::Request),
            "reply": schemars::schema_for!(gcoms_rpc_contract::Reply),
            "handle": schemars::schema_for!(gcoms_rpc_contract::OperationHandle),
            "fixtures": {"request": request, "reply": reply, "handle": handle},
        }))
        .expect("wire schemas")
    );
}
