use serde::{Deserialize, Serialize};
/// Public connection progress; never contains invitations or private routing cards.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkState {
    Locked,
    LocalOnly,
    InvitationRequired,
    Connecting,
    Connected,
    Reconnecting,
    InvitationExpired,
    Unavailable,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetworkStatus {
    pub state: NetworkState,
    pub message: String,
}
impl NetworkStatus {
    pub fn new(state: NetworkState) -> Self {
        let message = match state {
            NetworkState::Locked => "Unlock your identity to connect.",
            NetworkState::LocalOnly => "This instance uses an explicitly configured local network.",
            NetworkState::InvitationRequired => {
                "Import a network invitation from the person inviting you."
            }
            NetworkState::Connecting => "Connecting through the configured relays…",
            NetworkState::Connected => "Connected to the configured network.",
            NetworkState::Reconnecting => {
                "Relays are unavailable. Reconnecting; your identity and history are preserved."
            }
            NetworkState::InvitationExpired => {
                "Your network invitation has expired. Request a replacement invitation."
            }
            NetworkState::Unavailable => {
                "Network configuration is unavailable. Your identity and history are preserved."
            }
        };
        Self {
            state,
            message: message.into(),
        }
    }
}
