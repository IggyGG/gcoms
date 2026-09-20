//! Caller-supplied signed network trust. Applications own their network defaults.
pub use gcoms_network_client::InstalledNetwork;
pub fn from_json(bytes: &[u8]) -> Result<InstalledNetwork, String> {
    InstalledNetwork::from_json(bytes)
}
