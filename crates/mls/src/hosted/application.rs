use super::*;

/// Explicit dispatch classes; applications must never reinterpret a Notice or
/// Receipt as a command, ordinary chat or a topic mutation. All content stays
/// encrypted; only the class needed for authorization is public.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum HostedMessageKind {
    Text = 1,
    Action = 2,
    Notice = 3,
    Topic = 4,
    Nickname = 5,
    Presence = 6,
    Receipt = 7,
    File = 8,
    ContactOffer = 9,
}

impl HostedMessageKind {
    pub(super) fn wire_limit(self) -> usize {
        match self {
            Self::Receipt | Self::Nickname | Self::Presence => 4096,
            Self::Topic | Self::ContactOffer => 16 * 1024,
            _ => MAX_HOSTED_MESSAGE,
        }
    }
    pub(super) fn allowed(self, rules: &HostedRules, member: [u8; 32]) -> bool {
        match self {
            Self::Topic => rules.may_change_topic(member),
            Self::Receipt | Self::Nickname | Self::Presence => {
                !rules.closed() && rules.pending_removals().is_empty() && !rules.banned(member)
            }
            _ => rules.may_post(member),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_authority_and_inner_kind_survive_modified_client_and_moderation() {
        let root = IdentityKeypair::from_seed([100; 32]);
        let mut owner = HostedSession::create(&root, "owner", 64, true).unwrap();
        let mut public = HostedObserver::new(
            owner.policy.clone(),
            owner.policy.channel_id(),
            &owner.export_group_info().unwrap(),
        )
        .unwrap();
        let (mut alice, commit) = PreparedHostedJoin::new("alice")
            .unwrap()
            .join(&public, &JoinPermit::public(), 100)
            .unwrap();
        public = public
            .stage_join(&commit, alice.proposed_group_info().unwrap(), 100)
            .unwrap();
        owner.receive(&commit, 100).unwrap();
        alice.accept_join(&commit).unwrap();
        assert!(alice
            .send_kind(HostedMessageKind::Topic, b"unauthorized")
            .is_err());
        let mut forged = alice
            .send_kind(HostedMessageKind::Text, b"ordinary")
            .unwrap();
        let original = forged.clone();
        forged.kind = HostedMessageKind::Topic;
        forged.signature = alice.ctx.signer.sign(&forged.payload()).unwrap().into();
        assert!(public.verify_message(&forged).is_err());
        assert!(owner.receive_hosted(&forged).is_err());
        // Even an allowed public class cannot reclassify another inner kind.
        forged.kind = HostedMessageKind::Receipt;
        forged.signature = alice.ctx.signer.sign(&forged.payload()).unwrap().into();
        public.verify_message(&forged).unwrap();
        assert!(owner.receive_hosted(&forged).is_err());
        assert_eq!(owner.receive_hosted(&original).unwrap(), b"ordinary");
        for change in [
            HostedPolicyChange::Mode(HostedMode::Moderated, 1),
            HostedPolicyChange::Mode(HostedMode::TopicOperators, 0),
        ] {
            let control = owner.create_control(change, "policy").unwrap();
            public = public.stage_control(&control).unwrap();
            owner.apply_control(&control).unwrap();
            alice.apply_control(&control).unwrap();
        }
        assert!(alice.send_hosted(b"unvoiced").is_err());
        for kind in [
            HostedMessageKind::Topic,
            HostedMessageKind::Receipt,
            HostedMessageKind::Presence,
            HostedMessageKind::Nickname,
        ] {
            let message = alice.send_kind(kind, b"allowed class").unwrap();
            public.verify_message(&message).unwrap();
            assert_eq!(owner.receive_hosted(&message).unwrap(), b"allowed class");
        }
        assert!(alice
            .send_kind(HostedMessageKind::Notice, b"unvoiced notice")
            .is_err());
    }
}
