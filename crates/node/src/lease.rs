//! Compatibility path; shared wire codecs and retained-binding checks live in core.
pub use gcoms_core::lease::*;

#[cfg(feature = "client-persist")]
pub(crate) fn validate_retained_alias(
    alias: &crate::alias::OwnedAlias,
) -> Result<(), LeaseCodecError> {
    validate_retained_alias_renewal(alias, None)
}

#[cfg(feature = "client-persist")]
pub(crate) fn validate_retained_alias_renewal(
    alias: &crate::alias::OwnedAlias,
    renewal: Option<&[u8]>,
) -> Result<(), LeaseCodecError> {
    validate_retained_alias_binding(
        &RetainedAliasBinding {
            payload: &alias.lease_create.payload,
            relay_service_id: &alias.contact.target.relay_service_id,
            queue_id: alias.contact.queue_id,
            epoch: alias.contact.epoch,
            expiry: alias.contact.expiry,
            push_cap: alias.contact.push_cap,
            capabilities: alias.capabilities,
            create_path: &alias.create_path,
            limits: alias.limits,
        },
        renewal,
    )
}
