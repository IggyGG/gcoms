//! Single-use channel-invite redemption: the owner mints one invite and it can
//! be redeemed exactly once, even under a concurrent race.

use gcoms_node::channel::ChannelVisibility;
use gcoms_node::channel_invite::ChannelInvite;
use gcoms_node::node::{start, Ev, NodeConfig};

static NETWORK_TEST: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn spawn(seed: u8) -> gcoms_node::NodeHandle {
    start(NodeConfig {
        seed: [seed; 32],
        listen: "127.0.0.1:0".parse().unwrap(),
        control: None,
        advertise: None,
        inbox_relay: None,
        profile: gcoms_node::node::NodeProfile::fixture(),
        alias_lifecycle: Default::default(),
    })
    .await
    .expect("node start")
}

/// Build a redeemer's encoded join package (the bytes `redeem`/`admit` expect).
async fn join_package(member: &gcoms_node::NodeHandle, name: &str) -> (u64, Vec<u8>) {
    let req = member.prepare_channel_join(name).await.expect("prepare");
    let kp = member.channel_key_package(req).await.expect("kp");
    (req, kp)
}

#[tokio::test(flavor = "multi_thread")]
async fn invite_admits_a_member_and_then_is_spent() {
    let _guard = NETWORK_TEST.lock().await;
    let owner = spawn(0x41).await;
    let member = spawn(0x42).await;
    owner
        .create_channel("club", "founder", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    let (req, kp) = join_package(&member, "alice").await;

    let (id, secret, expiry) = owner.create_channel_invite("club", 3600).await.unwrap();
    assert!(expiry > 0);

    // First redemption succeeds and yields a usable Welcome.
    let welcome = owner
        .redeem_channel_invite("club", id, secret, &kp, "alice")
        .await
        .expect("first redemption");
    member
        .join_channel(req, "club", ChannelVisibility::Private, &welcome)
        .await
        .expect("member joins");

    // The SAME key package retried is an idempotent replay (same Welcome), not
    // a second consumption.
    let replay = owner
        .redeem_channel_invite("club", id, secret, &kp, "alice")
        .await
        .expect("idempotent replay");
    assert_eq!(replay, welcome);

    // A DIFFERENT member presenting the same invite is refused: it is spent.
    let intruder = spawn(0x43).await;
    let (_req2, kp2) = join_package(&intruder, "mallory").await;
    let err = owner
        .redeem_channel_invite("club", id, secret, &kp2, "mallory")
        .await
        .expect_err("invite is single-use");
    assert_eq!(err, "invite already used");

    owner.shutdown().await;
    member.shutdown().await;
    intruder.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn two_racing_redemptions_yield_exactly_one_success() {
    let _guard = NETWORK_TEST.lock().await;
    let owner = spawn(0x44).await;
    let first = spawn(0x45).await;
    let second = spawn(0x46).await;
    owner
        .create_channel("race", "founder", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    let (_r1, kp1) = join_package(&first, "one").await;
    let (_r2, kp2) = join_package(&second, "two").await;

    let (id, secret, _expiry) = owner.create_channel_invite("race", 3600).await.unwrap();

    // Fire both redemptions of the one invite concurrently. Per-channel command
    // serialization plus the consumed-flag check-and-set under the same lock
    // must let exactly one win.
    let owner_a = owner.clone();
    let owner_b = owner.clone();
    let kp_a = kp1.clone();
    let kp_b = kp2.clone();
    let a = tokio::spawn(async move {
        owner_a
            .redeem_channel_invite("race", id, secret, &kp_a, "one")
            .await
    });
    let b = tokio::spawn(async move {
        owner_b
            .redeem_channel_invite("race", id, secret, &kp_b, "two")
            .await
    });
    let ra = a.await.unwrap();
    let rb = b.await.unwrap();

    let successes = [&ra, &rb].iter().filter(|r| r.is_ok()).count();
    let rejections = [&ra, &rb]
        .iter()
        .filter(|r| matches!(r, Err(e) if e == "invite already used"))
        .count();
    assert_eq!(
        successes, 1,
        "exactly one redemption must succeed: {ra:?} {rb:?}"
    );
    assert_eq!(
        rejections, 1,
        "the loser must be told the invite was used: {ra:?} {rb:?}"
    );

    owner.shutdown().await;
    first.shutdown().await;
    second.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_invite_is_refused() {
    let _guard = NETWORK_TEST.lock().await;
    let owner = spawn(0x47).await;
    let member = spawn(0x48).await;
    owner
        .create_channel("timed", "founder", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    let (_req, kp) = join_package(&member, "late").await;

    // TTL clamps to at least 1s; wait it out so the invite is expired at redeem.
    let (id, secret, _expiry) = owner.create_channel_invite("timed", 1).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let err = owner
        .redeem_channel_invite("timed", id, secret, &kp, "late")
        .await
        .expect_err("expired");
    assert_eq!(err, "invite expired");

    owner.shutdown().await;
    member.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_secret_and_unknown_id_are_refused() {
    let _guard = NETWORK_TEST.lock().await;
    let owner = spawn(0x49).await;
    let member = spawn(0x4a).await;
    owner
        .create_channel("guard", "founder", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    let (_req, kp) = join_package(&member, "who").await;
    let (id, secret, _expiry) = owner.create_channel_invite("guard", 3600).await.unwrap();

    // Wrong secret for a real id: indistinguishable from an unknown id.
    let mut bad_secret = secret;
    bad_secret[0] ^= 0xff;
    let err = owner
        .redeem_channel_invite("guard", id, bad_secret, &kp, "who")
        .await
        .expect_err("wrong secret");
    assert_eq!(err, "invite not found");

    // Unknown id entirely.
    let err = owner
        .redeem_channel_invite("guard", [0u8; 16], secret, &kp, "who")
        .await
        .expect_err("unknown id");
    assert_eq!(err, "invite not found");

    // The real invite still works afterward (a failed guess did not spend it).
    owner
        .redeem_channel_invite("guard", id, secret, &kp, "who")
        .await
        .expect("valid redemption after failed guesses");

    owner.shutdown().await;
    member.shutdown().await;
}

/// The full end-to-end flow a friend actually uses: parse a link, redeem it
/// over the relay (owner online), join, and exchange a message — no manual
/// key-package/Welcome hand-carrying.
#[tokio::test(flavor = "multi_thread")]
async fn friend_redeems_a_link_over_the_relay_and_joins() {
    let _guard = NETWORK_TEST.lock().await;
    let owner = spawn(0x51).await;
    let friend = spawn(0x52).await;
    owner
        .create_channel("club", "founder", 8, ChannelVisibility::Private)
        .await
        .unwrap();

    // Owner mints an invite and builds a shareable link carrying its own public
    // contact card.
    let (id, secret, expiry) = owner.create_channel_invite("club", 3600).await.unwrap();
    let owner_info = owner.current_info().await.unwrap();
    let link = ChannelInvite {
        owner: owner_info,
        channel: "club".into(),
        id,
        secret,
        expiry,
    }
    .to_link()
    .unwrap();

    // Friend parses the link, prepares its own key package, and redeems over
    // the relay — the owner's invite service admits it and returns the Welcome.
    let invite = ChannelInvite::from_link(&link).expect("valid link");
    let mut owner_events = owner.subscribe();
    let req = friend.prepare_channel_join("alice").await.unwrap();
    let kp = friend.channel_key_package(req).await.unwrap();
    let welcome = friend
        .redeem_invite_remote(
            invite.owner.clone(),
            &invite.channel,
            "alice",
            &kp,
            invite.id,
            invite.secret,
            30,
        )
        .await
        .expect("remote redemption succeeds");
    friend
        .join_channel(req, "club", ChannelVisibility::Private, &welcome)
        .await
        .expect("friend joins");

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if matches!(owner_events.recv().await.unwrap(), Ev::ChannelRosterChanged { channel, .. } if channel == "club") {
                break;
            }
        }
    }).await.expect("remote admission must notify the owner's attached clients");

    // The channel now works: an owner message reaches the friend.
    owner
        .send_channel_text("club", b"welcome in")
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let ev = tokio::time::timeout_at(deadline, friend.next_event())
            .await
            .expect("timeout waiting for channel message")
            .expect("node ended");
        if let Ev::ChannelMessage { channel, text, .. } = ev {
            if channel == "club" && text == b"welcome in" {
                break;
            }
        }
    }

    // The link is now spent: a second friend cannot reuse it.
    let intruder = spawn(0x53).await;
    let req2 = intruder.prepare_channel_join("mallory").await.unwrap();
    let kp2 = intruder.channel_key_package(req2).await.unwrap();
    let err = intruder
        .redeem_invite_remote(
            invite.owner.clone(),
            &invite.channel,
            "mallory",
            &kp2,
            invite.id,
            invite.secret,
            30,
        )
        .await
        .expect_err("spent link is refused");
    assert_eq!(err, "invite already used");

    owner.shutdown().await;
    friend.shutdown().await;
    intruder.shutdown().await;
}

/// Build an invite link for a channel the owner owns.
async fn link_for(owner: &gcoms_node::NodeHandle, channel: &str, ttl: u64) -> ChannelInvite {
    let (id, secret, expiry) = owner.create_channel_invite(channel, ttl).await.unwrap();
    ChannelInvite {
        owner: owner.current_info().await.unwrap(),
        channel: channel.into(),
        id,
        secret,
        expiry,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_redeem_of_an_expired_link_is_refused() {
    let _guard = NETWORK_TEST.lock().await;
    let owner = spawn(0x54).await;
    let friend = spawn(0x55).await;
    owner
        .create_channel("timed", "founder", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    let invite = link_for(&owner, "timed", 1).await;
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let (req, kp) = join_package(&friend, "late").await;
    let _ = req;
    let err = friend
        .redeem_invite_remote(
            invite.owner.clone(),
            &invite.channel,
            "late",
            &kp,
            invite.id,
            invite.secret,
            30,
        )
        .await
        .expect_err("expired");
    assert_eq!(err, "invite expired");
    owner.shutdown().await;
    friend.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_redeem_with_a_wrong_secret_is_refused() {
    let _guard = NETWORK_TEST.lock().await;
    let owner = spawn(0x56).await;
    let friend = spawn(0x57).await;
    owner
        .create_channel("guard", "founder", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    let invite = link_for(&owner, "guard", 3600).await;
    let (_req, kp) = join_package(&friend, "who").await;
    let mut bad = invite.secret;
    bad[0] ^= 0xff;
    let err = friend
        .redeem_invite_remote(
            invite.owner.clone(),
            &invite.channel,
            "who",
            &kp,
            invite.id,
            bad,
            30,
        )
        .await
        .expect_err("wrong secret");
    assert_eq!(err, "invite not found");
    owner.shutdown().await;
    friend.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_redeem_times_out_when_the_owner_is_offline() {
    let _guard = NETWORK_TEST.lock().await;
    let owner = spawn(0x58).await;
    let friend = spawn(0x59).await;
    owner
        .create_channel("away", "founder", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    let invite = link_for(&owner, "away", 3600).await;
    // Take the owner offline before the friend redeems: the request cannot be
    // serviced, so the friend must time out cleanly (not hang, not succeed).
    owner.shutdown().await;
    let (_req, kp) = join_package(&friend, "alice").await;
    let err = friend
        .redeem_invite_remote(
            invite.owner.clone(),
            &invite.channel,
            "alice",
            &kp,
            invite.id,
            invite.secret,
            2,
        )
        .await
        .expect_err("owner offline");
    assert!(
        err.contains("timed out"),
        "expected a timeout message, got: {err}"
    );
    friend.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_link_pointed_at_the_wrong_owner_does_not_redeem() {
    let _guard = NETWORK_TEST.lock().await;
    let owner = spawn(0x5a).await;
    let other = spawn(0x5b).await;
    let friend = spawn(0x5c).await;
    owner
        .create_channel("real", "founder", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    // `other` also owns a channel, so it is a live node that can be addressed.
    other
        .create_channel("decoy", "founder", 8, ChannelVisibility::Private)
        .await
        .unwrap();
    let invite = link_for(&owner, "real", 3600).await;
    // Swap the owner card for a different valid node: the secret is not a bearer
    // capability against an attacker-chosen owner — `other` has no such invite.
    let other_info = other.current_info().await.unwrap();
    let (_req, kp) = join_package(&friend, "alice").await;
    let err = friend
        .redeem_invite_remote(
            other_info,
            &invite.channel,
            "alice",
            &kp,
            invite.id,
            invite.secret,
            5,
        )
        .await
        .expect_err("wrong owner cannot honour the invite");
    // `other` has no channel "real" and no such invite -> not found / no channel.
    assert!(
        err == "invite not found" || err == "no channel",
        "unexpected error: {err}"
    );
    owner.shutdown().await;
    other.shutdown().await;
    friend.shutdown().await;
}
