//! Local operator commands. Secrets are written to explicit files, never stdout.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use gcoms_catalog::network::{atomic_json, read_grants, token_digest, GrantFile, GrantRecord};
use gcoms_crypto::IdentityKeypair;
use gcoms_network::{
    NetworkDefaults, NetworkInvitation, SignedNetworkDefaults, SigningKeyTransition,
};
use rand::RngCore;
use serde::Deserialize;
use std::{
    fs::File,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantRequest {
    network_id: String,
    provider_urls: Vec<String>,
    expires_at: u64,
    scopes: Vec<String>,
    max_names: u32,
}
fn read<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, String> {
    serde_json::from_slice(&std::fs::read(path).map_err(|_| "cannot read input file")?)
        .map_err(|_| "invalid JSON input".into())
}
fn signer(path: &str) -> Result<IdentityKeypair, String> {
    let seed: [u8; 32] = std::fs::read(path)
        .map_err(|_| "cannot read signing seed")?
        .try_into()
        .map_err(|_| "signing seed must be exactly 32 raw bytes")?;
    Ok(IdentityKeypair::from_seed(seed))
}
fn new_file(path: &str, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "output must be a new file in an existing private directory")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "cannot write output")
        .and_then(|_| {
            File::open(Path::new(path).parent().ok_or("output needs a parent")?)
                .and_then(|f| f.sync_all())
                .map_err(|_| "cannot sync output directory")
        })
        .map_err(String::from)
}
fn lock(path: &str) -> Result<File, String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(format!("{path}.lock"))
        .map_err(|_| "cannot lock grant store")?;
    file.try_lock().map_err(|_| "grant store is busy")?;
    Ok(file)
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["keygen",seed_path,pub_path] => {let key=IdentityKeypair::generate();new_file(seed_path,key.seed().as_slice())?;new_file(pub_path,&key.public_bytes())?;}
        ["sign",defaults_path,seed_path,transitions_path,out] => {
            let defaults:NetworkDefaults=read(defaults_path)?;defaults.validate_at(now(),0)?;
            let transitions=if *transitions_path=="-" {vec![]}else{read(transitions_path)?};
            let signed=SignedNetworkDefaults::sign(defaults,&signer(seed_path)?,transitions)?;
            new_file(out,&serde_json::to_vec(&signed).map_err(|_|"cannot encode defaults")?)?;
        }
        ["transition",network,old_seed,new_public,not_before,expires,out] => {
            let value=SigningKeyTransition::sign(network.to_string(),not_before.parse().map_err(|_|"invalid not-before")?,expires.parse().map_err(|_|"invalid expiry")?,&std::fs::read(new_public).map_err(|_|"cannot read new public key")?,&signer(old_seed)?)?;
            new_file(out,&serde_json::to_vec(&value).map_err(|_|"cannot encode transition")?)?;
        }
        ["grant",store,request_path,out] => {
            let _lock=lock(store)?;let request:GrantRequest=read(request_path)?;
            if request.expires_at<=now() || request.max_names>1000 || request.scopes.is_empty() || request.scopes.len()>10
                || request.scopes.iter().any(|s|s!="bootstrap" && s!="names" && !(1..=8).any(|n|s==&format!("server:r{n}"))) {return Err("invalid grant scope, expiry or name quota".into());}
            let mut grants=if Path::new(store).exists(){read_grants(Path::new(store))?}else{GrantFile{version:1,grants:vec![]}};
            if grants.grants.len()>=10_000 {return Err("grant store is full".into());}
            let mut secret=[0;32];rand::thread_rng().fill_bytes(&mut secret);let token=URL_SAFE_NO_PAD.encode(secret);
            let invite=NetworkInvitation{version:1,network_id:request.network_id,provider_urls:request.provider_urls,grant:token.clone(),expires_at:request.expires_at};
            let code=invite.encode()?;NetworkInvitation::decode_at(&code,now())?;
            let grant=GrantRecord{id:token_digest(&token)?,expires_at:request.expires_at,scopes:request.scopes,max_names:request.max_names,revoked:false};
            // Reserve the output before committing the grant; a failed state
            // write leaves an unusable invitation, never an unreported live grant.
            new_file(out,code.as_bytes())?;grants.grants.push(grant);atomic_json(Path::new(store),&grants)?;
        }
        ["revoke",store,id] => {let _lock=lock(store)?;let mut grants=read_grants(Path::new(store))?;let grant=grants.grants.iter_mut().find(|g|g.id==*id).ok_or("unknown grant digest")?;grant.revoked=true;atomic_json(Path::new(store),&grants)?;}
        ["verify",defaults,key,network,sequence] => {
            let signed:SignedNetworkDefaults=read(defaults)?;signed.verify_at(&std::fs::read(key).map_err(|_|"cannot read verification key")?,network,now(),sequence.parse().map_err(|_|"invalid minimum sequence")?)?;
        }
        _=>return Err("usage: gc-network-operator keygen SEED_NEW PUBLIC_NEW | sign DEFAULTS_JSON SEED TRANSITIONS_JSON_OR_- SIGNED_NEW | transition NETWORK OLD_SEED NEW_PUBLIC NOT_BEFORE EXPIRY TRANSITION_NEW | grant GRANTS_JSON REQUEST_JSON INVITATION_NEW | revoke GRANTS_JSON GRANT_DIGEST | verify SIGNED_JSON PUBLIC_KEY NETWORK MIN_SEQUENCE".into()),
    }
    Ok(())
}
