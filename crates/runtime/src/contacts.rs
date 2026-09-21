//! Opaque application contact helpers; private relay cards stay separate from peer identities.
pub fn decode_relay_card(encoded: &str) -> Result<gcoms_sdk::RelayCard, String> {
    let card = gcoms_sdk::RelayCard(encoded.trim().as_bytes().to_vec());
    relay_node(&card)?;
    Ok(card)
}
pub(crate) fn relay_node(
    card: &gcoms_sdk::RelayCard,
) -> Result<gcoms_node::proto::NodeInfo, String> {
    gcoms_node::proto::private_info_from_b64(
        std::str::from_utf8(&card.0).map_err(|_| "invalid relay card")?,
    )
    .ok_or_else(|| "invalid relay card".into())
}
pub fn decode_contact_card(encoded: &str) -> Result<gcoms_sdk::ContactCard, String> {
    gcoms_node::proto::info_from_b64(encoded.trim()).ok_or("invalid contact card")?;
    Ok(gcoms_sdk::ContactCard(encoded.trim().as_bytes().to_vec()))
}
pub fn relay_label(card: &gcoms_sdk::RelayCard) -> Result<String, String> {
    Ok(relay_node(card)?
        .aliases
        .first()
        .map_or_else(|| "relay".into(), |a| a.target.address.to_string()))
}

/// Local inspection details, separate from the stable serialized SDK invitation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelInvitationDetails {
    pub invitation: gcoms_sdk::ChannelInvitation,
    /// `None` means no current-protocol bootstrap was supplied. These identifiers
    /// must be checked against the selected signed network by the application;
    /// inspection alone does not authenticate or authorize a network switch.
    pub current_bootstrap_relays: Option<Vec<[u8; 32]>>,
}

pub fn inspect_channel_invitation_details(link: &str) -> Result<ChannelInvitationDetails, String> {
    let envelope = gcoms_node::channel_invite::InviteEnvelope::from_link(link.trim())
        .ok_or("invalid invitation")?;
    #[cfg(feature = "gc2-carrier")]
    let current_bootstrap_relays = envelope
        .gc2_bootstrap
        .as_ref()
        .map(|bundle| bundle.relays.iter().map(|relay| relay.service_id).collect());
    #[cfg(not(feature = "gc2-carrier"))]
    let current_bootstrap_relays = None;
    let invite = envelope.invite;
    Ok(ChannelInvitationDetails {
        invitation: gcoms_sdk::ChannelInvitation {
            link: link.trim().into(),
            channel: invite.channel,
            expires_at: invite.expiry,
            local_only: invite.owner.aliases.iter().all(|a| {
                a.target.address.ip().is_loopback() || a.target.address.ip().is_unspecified()
            }),
        },
        current_bootstrap_relays,
    })
}

pub fn inspect_channel_invitation(link: &str) -> Result<gcoms_sdk::ChannelInvitation, String> {
    inspect_channel_invitation_details(link).map(|details| details.invitation)
}

/// Apply exactly the node's metadata validation before any application prompt.
pub fn validate_channel_change(change: &gcoms_sdk::ChannelChange) -> Result<(), String> {
    use gcoms_node::channel::ChannelChange;
    let change = match change {
        gcoms_sdk::ChannelChange::Topic(text) => ChannelChange::Topic(text.clone()),
        gcoms_sdk::ChannelChange::Nickname(text) => ChannelChange::Nickname(text.clone()),
        gcoms_sdk::ChannelChange::Transfer(member) => ChannelChange::Transfer(*member),
        gcoms_sdk::ChannelChange::Leave => ChannelChange::Leave,
        gcoms_sdk::ChannelChange::Close => ChannelChange::Close,
    };
    change.validate()
}

pub async fn fetch_relay_provision(
    endpoints: &[url::Url],
    ephemeral: bool,
) -> Result<gcoms_sdk::RelayCard, String> {
    let node = crate::bootstrap::fetch_relay_provision(endpoints, ephemeral).await?;
    use base64::Engine;
    let bytes = gcoms_node::proto::NodeInfo::encode_private(&node).ok_or("invalid relay card")?;
    Ok(gcoms_sdk::RelayCard(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(bytes)
            .into_bytes(),
    ))
}
pub fn validate_catalog_request(method: &str, url: &str, body: &[u8]) -> Result<(), String> {
    gcoms_routing::catalog::validate(method, url, body)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invitation() -> gcoms_node::channel_invite::ChannelInvite {
        gcoms_node::channel_invite::ChannelInvite {
            owner: gcoms_node::proto::NodeInfo {
                identity_pk: vec![1; 48],
                bundle: vec![2; 96],
                aliases: vec![],
                provisioning: None,
            },
            channel: "friends".into(),
            id: [3; 16],
            secret: [4; 32],
            expiry: 1_800_000_300,
        }
    }

    #[test]
    fn invitation_details_distinguish_absent_current_bootstrap() {
        let invite = invitation();
        for link in [
            invite.to_link().unwrap(),
            invite
                .to_link_with_bootstrap(gcoms_routing::bootstrap::BootstrapBundle {
                    relays: vec![gcoms_routing::Relay {
                        addr: "192.0.2.10:443".parse().unwrap(),
                        service_id: [10; 32],
                        reentry_cap: [11; 32],
                        circuit_cap: [12; 32],
                        expires_at: 1_800_000_000,
                    }],
                })
                .unwrap(),
        ] {
            let details = inspect_channel_invitation_details(&format!(" {link}\n")).unwrap();
            assert_eq!(details.current_bootstrap_relays, None);
            assert_eq!(details.invitation.channel, "friends");
            assert_eq!(details.invitation.expires_at, invite.expiry);
            assert_eq!(
                details.invitation,
                inspect_channel_invitation(&link).unwrap()
            );
        }
        assert!(inspect_channel_invitation_details("invalid!").is_err());
    }

    #[cfg(feature = "gc2-carrier")]
    #[test]
    fn invitation_details_preserve_exact_current_service_ids_without_capabilities() {
        let invite = invitation();
        let bundle = gcoms_routing::gc2::directory::BootstrapBundle {
            relays: (1..=3)
                .map(|n| {
                    gcoms_routing::service::gc2_introduction_from(
                        format!("192.0.2.{n}:443").parse().unwrap(),
                        [n; 32],
                        &[n + 10; 32],
                        1_800_000_000,
                    )
                })
                .collect(),
        };
        let link = invite.to_link_with_gc2_bootstrap(bundle).unwrap();
        let details = inspect_channel_invitation_details(&link).unwrap();
        assert_eq!(
            details.current_bootstrap_relays,
            Some(vec![[1; 32], [2; 32], [3; 32]])
        );
        assert_eq!(
            details.invitation,
            inspect_channel_invitation(&link).unwrap()
        );
        // The existing wire type must remain a four-field object.
        let value = serde_json::to_value(details.invitation).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 4);
    }

    #[test]
    fn channel_change_validation_retains_node_text_bounds() {
        use gcoms_sdk::ChannelChange::*;
        for change in [
            Topic(String::new()),
            Topic("t".repeat(512)),
            Nickname("n".repeat(64)),
            Transfer([0; 32]),
            Leave,
            Close,
        ] {
            validate_channel_change(&change).unwrap();
        }
        for change in [
            Topic("t".repeat(513)),
            Topic("line\nbreak".into()),
            Nickname(" ".into()),
            Nickname("n".repeat(65)),
            Nickname("\0".into()),
        ] {
            assert!(validate_channel_change(&change).is_err(), "{change:?}");
        }
    }
}
