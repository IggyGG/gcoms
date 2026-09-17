use std::process::Command;

#[test]
fn gate_failure_returns_nonzero() {
    let output = Command::new(env!("CARGO_BIN_EXE_gcoms-sim"))
        .args(["10", "0"])
        .output()
        .expect("run gc-sim");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("G-M5 overall: FAIL"));
}
