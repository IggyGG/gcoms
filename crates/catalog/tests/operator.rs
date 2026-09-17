use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use gcoms_catalog::network::{read_grants, token_digest};
use gcoms_network::{Founder, NetworkDefaults, NetworkInvitation};
use std::{
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_gc-network-operator"))
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn operator_preserves_keys_signs_and_revokes_without_exposing_secret_output() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let dir = std::env::temp_dir().join(format!(
        "gc-network-operator-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    let path = |name: &str| -> String { dir.join(name).to_str().unwrap().into() };
    let seed = path("seed");
    let public = path("public");
    let output = run(&["keygen", &seed, &public]);
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    gcoms_private_fs::validate_private_file(std::path::Path::new(&seed), "signing seed").unwrap();
    let original = std::fs::read(&seed).unwrap();
    assert_eq!(original.len(), 32);
    assert!(!run(&["keygen", &seed, &public]).status.success());
    assert_eq!(std::fs::read(&seed).unwrap(), original);
    let defaults = NetworkDefaults {
        version: 1,
        network_id: "gchat.boo".into(),
        sequence: 9,
        issued_at: now,
        expires_at: now + 3600,
        provider_urls: vec!["https://bootstrap-hel.gchat.boo/".into()],
        founders: vec![Founder {
            name: "r1.relays.gchat.boo".into(),
            service_id: [1; 32],
            address_hints: vec!["8.8.8.8:4433".parse().unwrap()],
        }],
        dns_domain: "gchat.boo".into(),
    };
    std::fs::write(path("defaults"), serde_json::to_vec(&defaults).unwrap()).unwrap();
    let signed = path("signed");
    assert!(run(&["sign", &path("defaults"), &seed, "-", &signed])
        .status
        .success());
    assert!(run(&["verify", &signed, &public, "gchat.boo", "9"])
        .status
        .success());
    assert!(!run(&["verify", &signed, &public, "gchat.boo", "10"])
        .status
        .success());
    std::fs::write(path("grant-request"),serde_json::to_vec(&serde_json::json!({"network_id":"gchat.boo","provider_urls":defaults.provider_urls,"expires_at":now+1800,"scopes":["bootstrap","names"],"max_names":1})).unwrap()).unwrap();
    let grants = path("grants");
    let invitation = path("invitation");
    let output = run(&["grant", &grants, &path("grant-request"), &invitation]);
    assert!(output.status.success(), "{:?}", output.stderr);
    assert!(output.stdout.is_empty());
    let code = std::fs::read_to_string(&invitation).unwrap();
    let invitation = NetworkInvitation::decode_at(&code, now).unwrap();
    assert_eq!(URL_SAFE_NO_PAD.decode(&invitation.grant).unwrap().len(), 32);
    assert!(!std::fs::read_to_string(&grants)
        .unwrap()
        .contains(&invitation.grant));
    let id = token_digest(&invitation.grant).unwrap();
    assert!(run(&["revoke", &grants, &id]).status.success());
    let store = read_grants(&PathBuf::from(grants)).unwrap();
    assert!(store.grants[0].revoked);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&seed).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}
