//! Published DS-MIN v1 domains. Bootstrap applications are volatile and do not
//! confer chat, managed-machine or arbitrary relay-forwarding authority.
//! Reserved compatibility constants; private installer implementation is excluded.
pub const VERSION: u8 = 1;
pub const CONTENT_TYPE: &str = "application/vnd.ghost.bootstrap.v1";
pub const REQUEST_DOMAIN: &str = "ghost.dropship.bootstrap.request.v1";
pub const REPLY_DOMAIN: &str = "ghost.dropship.bootstrap.reply.v1";
pub const REFRESH_DOMAIN: &str = "ghost.dropship.bootstrap.refresh.v1";
pub const LAUNCH_DOMAIN: &str = "ghost.dropship.bootstrap.launch.v1";
pub const RECEIPT_DOMAIN: &str = "ghost.dropship.bootstrap.receipt.v1";
pub const CONTACT_DOMAIN: &str = "ghost.dropship.bootstrap.contact.v1";
pub const RELAY_ADMISSION_DOMAIN: &str = "ghost.dropship.bootstrap.relay-admission.v1";
/// Additional RelaySub operations; legacy lease operation ordinals do not move.
pub const OP_RELAY_CHALLENGE: u8 = 7;
pub const OP_RELAY_ADMISSION: u8 = 8;
pub const MAX_CONTROL_BYTES: usize = 32_768;
pub const CONTROL_PAGE_BYTES: usize = 8192;
/// Matches the existing CMD D13 sender's bounded object source.
pub const MAX_ARTIFACT_BYTES: u64 = 67_108_864;
pub const MAX_PROOF_LIFETIME_SECONDS: u64 = 300;
pub const DEFAULT_TRANSFER_TIMEOUT_SECONDS: u64 = 18_000;
pub const DEFAULT_HANDOFF_LIFETIME_SECONDS: u64 = 900;
pub const REPORT_TIMEOUT_SECONDS: u64 = 120;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bootstrap_domains_match_the_published_cross_language_contract() {
        let contract = include_str!("../fixtures/bootstrap-v1.json");
        for value in [
            CONTENT_TYPE,
            REQUEST_DOMAIN,
            REPLY_DOMAIN,
            REFRESH_DOMAIN,
            LAUNCH_DOMAIN,
            RECEIPT_DOMAIN,
            CONTACT_DOMAIN,
            RELAY_ADMISSION_DOMAIN,
        ] {
            assert!(contract.contains(&alloc::format!("\"{value}\"")));
        }
        for (field, value) in [
            ("version", VERSION as u64),
            ("relayChallengeOperation", OP_RELAY_CHALLENGE as u64),
            ("relayAdmissionOperation", OP_RELAY_ADMISSION as u64),
            ("maxControlBytes", MAX_CONTROL_BYTES as u64),
            ("controlPageBytes", CONTROL_PAGE_BYTES as u64),
            ("maxArtifactBytes", MAX_ARTIFACT_BYTES),
            ("maxProofLifetimeSeconds", MAX_PROOF_LIFETIME_SECONDS),
            (
                "defaultTransferTimeoutSeconds",
                DEFAULT_TRANSFER_TIMEOUT_SECONDS,
            ),
            (
                "defaultHandoffLifetimeSeconds",
                DEFAULT_HANDOFF_LIFETIME_SECONDS,
            ),
            ("reportTimeoutSeconds", REPORT_TIMEOUT_SECONDS),
        ] {
            assert!(contract.contains(&alloc::format!("\"{field}\": {value},")));
        }
    }
}
