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

pub fn inspect_channel_invitation(link: &str) -> Result<gcoms_sdk::ChannelInvitation, String> {
    let invite = gcoms_node::channel_invite::ChannelInvite::from_link(link.trim())
        .ok_or("invalid invitation")?;
    Ok(gcoms_sdk::ChannelInvitation {
        link: link.trim().into(),
        channel: invite.channel,
        expires_at: invite.expiry,
        local_only: invite
            .owner
            .aliases
            .iter()
            .all(|a| a.target.address.ip().is_loopback() || a.target.address.ip().is_unspecified()),
    })
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
