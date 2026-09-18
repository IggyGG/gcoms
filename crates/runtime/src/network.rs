//! GComs application API default network. GComs accepts caller-supplied trust.
pub fn installed() -> Result<gcoms_network_client::InstalledNetwork, String> {
    gcoms_network_client::InstalledNetwork::from_json(include_bytes!(
        "../assets/gchat-network.json"
    ))
}
pub fn provider_urls() -> Result<Vec<String>, String> {
    let network = installed()?;
    Ok(network
        .defaults_at(network.signed_defaults.defaults.issued_at, 0)?
        .provider_urls)
}

pub use gcoms_network_client::InstalledNetwork;
pub fn from_json(bytes: &[u8]) -> Result<InstalledNetwork, String> {
    InstalledNetwork::from_json(bytes)
}
