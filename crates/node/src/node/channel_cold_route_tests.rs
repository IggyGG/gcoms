use super::*;
use crate::node::{start_persistent, start_persistent_restored, NodeConfig, NodeProfile};
use std::time::Duration;

fn config(seed: [u8; 32], listen: std::net::SocketAddr) -> NodeConfig {
    NodeConfig {
        seed,
        listen,
        control: None,
        advertise: None,
        inbox_relay: None,
        profile: NodeProfile::fixture(),
        alias_lifecycle: Default::default(),
    }
}
fn fixture_sink() -> DurableStateSink {
    Arc::new(|_| Ok(()))
}
fn expire_owned(bytes: &[u8], seed: &[u8; 32], name: &str) -> Vec<u8> {
    let mut archive = decode_v2(bytes, seed).unwrap();
    let own = archive.channel_routes.get_mut(name).unwrap();
    let expiry = now_unix() - 1;
    own.public.data.expiry = expiry;
    own.public.control.expiry = expiry;
    for alias in &mut own.aliases {
        alias.contact.expiry = expiry;
    }
    replace_v18_owned_route(bytes, seed, name, own).unwrap()
}
async fn wait_text(node: &NodeHandle, body: &[u8]) -> [u8; 16] {
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            if let Some(Ev::ChannelMessage { text, msg_id, .. }) = node.next_event().await {
                if text == body {
                    return msg_id;
                }
            }
        }
    })
    .await
    .expect("real channel plaintext")
}
async fn wait_ack(node: &NodeHandle, wanted: [u8; 16]) {
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            if matches!(node.next_event().await, Some(Ev::ChannelDelivery { msg_id, .. }) if msg_id == wanted) { return; }
        }
    }).await.expect("real authenticated all-member ACK")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_both_expired_channel_queues_recover_over_bound_base_contact() {
    let name = "retained-cold-channel";
    let a_seed = [0xb1; 32];
    let b_seed = [0xb2; 32];
    let owner = start_persistent(
        config(a_seed, "127.0.0.1:0".parse().unwrap()),
        fixture_sink(),
    )
    .await
    .unwrap();
    let member = start_persistent(
        config(b_seed, "127.0.0.1:0".parse().unwrap()),
        fixture_sink(),
    )
    .await
    .unwrap();
    let a_addr = owner.info.primary().unwrap().target.address;
    let b_addr = member.info.primary().unwrap().target.address;
    let initial = async {
        let channel_id = owner
            .create_channel(name, "owner", 8, crate::channel::ChannelVisibility::Private)
            .await?;
        let request = member.prepare_channel_join("member").await?;
        let package = member.channel_key_package(request).await?;
        let welcome = owner.admit_channel(name, &package, "member").await?;
        member
            .join_channel(
                request,
                name,
                crate::channel::ChannelVisibility::Private,
                &welcome,
            )
            .await?;
        let initial_id = owner
            .send_channel_text_tracked(name, b"retained before restart")
            .await?;
        if wait_text(&member, b"retained before restart").await != initial_id {
            return Err("initial wire mismatch".into());
        }
        wait_ack(&owner, initial_id).await;
        Ok::<_, String>((
            channel_id,
            welcome,
            owner.export_state().await?,
            member.export_state().await?,
        ))
    }
    .await;
    owner.shutdown().await;
    member.shutdown().await;
    let (id, welcome, a_before, b_before) = initial.unwrap();
    let a_old = decode_v2(&a_before, &a_seed).unwrap();
    let b_old = decode_v2(&b_before, &b_seed).unwrap();
    let epoch = a_old.channels[0].role.epoch();
    let a_state = expire_owned(&a_before, &a_seed, name);
    let b_state = expire_owned(&b_before, &b_seed, name);
    let owner =
        start_persistent_restored(config(a_seed, a_addr), None, fixture_sink(), Some(&a_state))
            .await
            .unwrap();
    let member =
        start_persistent_restored(config(b_seed, b_addr), None, fixture_sink(), Some(&b_state))
            .await
            .unwrap();
    let result = async {
        let a_new = decode_v2(&owner.export_state().await?, &a_seed)?;
        let b_new = decode_v2(&member.export_state().await?, &b_seed)?;
        for (old_archive, new_archive) in [(&a_old, &a_new), (&b_old, &b_new)] {
            let old = &old_archive.channels[0];
            let new = &new_archive.channels[0];
            assert_eq!(old.role.channel_id(), new.role.channel_id());
            assert_eq!(old.role.own_pseudonym(), new.role.own_pseudonym());
            assert_eq!(old.role.epoch(), new.role.epoch());
            assert_eq!(old.role.roster(), new.role.roster());
            assert_ne!(
                old_archive.channel_routes[name].public.data.queue_id,
                new_archive.channel_routes[name].public.data.queue_id
            );
            assert!(new_archive.previous_channel_routes[name].public.data.expiry < now_unix());
        }
        assert_eq!(
            owner.info.identity_pk,
            owner.current_info().await?.identity_pk
        );
        let peer = member.current_info().await?;
        for (other_id, other_epoch, other_welcome) in [
            (
                crate::channel::ChannelId([0x66; 32]),
                epoch,
                welcome.clone(),
            ),
            (id, epoch + 1, welcome.clone()),
            (id, epoch, b"unrelated Welcome".to_vec()),
        ] {
            assert!(owner
                .recover_channel_route(name, other_id, other_epoch, &other_welcome, &peer)
                .await
                .is_err());
        }
        let refusal = owner
            .send_channel_text_tracked(name, b"pending across route repair")
            .await
            .expect_err("expired channel queue must refuse the actual send");
        assert!(refusal.contains("channel send failed"));
        let retained = decode_v2(&owner.export_state().await?, &a_seed)?;
        assert_eq!(retained.channels[0].message_outbox.len(), 1);
        let before_wire = retained.channels[0].message_outbox[0].0;
        assert!(
            tokio::time::timeout(Duration::from_millis(400), async {
                loop {
                    if let Some(Ev::ChannelMessage { text, .. }) = member.next_event().await {
                        if text == b"pending across route repair" {
                            break;
                        }
                    }
                }
            })
            .await
            .is_err(),
            "expired peer queues unexpectedly delivered before recovery"
        );
        let announced = owner
            .recover_channel_route(name, id, epoch, &welcome, &peer)
            .await?;
        assert_eq!(
            announced,
            owner
                .recover_channel_route(name, id, epoch, &welcome, &peer)
                .await?,
            "exact retry must reuse MLS ciphertext"
        );
        let recovered = wait_text(&member, b"pending across route repair").await;
        assert_eq!(
            before_wire, recovered,
            "retained application wire ID changed"
        );
        wait_ack(&owner, before_wire).await;
        let reverse = member
            .send_channel_text_tracked(name, b"reverse path recovered")
            .await?;
        assert_eq!(wait_text(&owner, b"reverse path recovered").await, reverse);
        wait_ack(&member, reverse).await;
        let a_after = decode_v2(&owner.export_state().await?, &a_seed)?;
        let b_after = decode_v2(&member.export_state().await?, &b_seed)?;
        assert_eq!(a_after.channels[0].role.epoch(), epoch);
        assert_eq!(b_after.channels[0].role.epoch(), epoch);
        assert_eq!(
            a_after.channels[0].role.roster(),
            a_old.channels[0].role.roster()
        );
        assert_eq!(
            b_after.channels[0].role.roster(),
            b_old.channels[0].role.roster()
        );
        assert!(a_after.channels[0].message_outbox.is_empty());
        assert!(b_after.channels[0].message_outbox.is_empty());
        Ok::<_, String>(())
    }
    .await;
    owner.shutdown().await;
    member.shutdown().await;
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_near_expiry_member_accepts_owner_directory_and_original_membership_ack() {
    let name = "cold-expiring-reply";
    let a_seed = [0xc1; 32];
    let b_seed = [0xc2; 32];
    let owner = start_persistent(
        config(a_seed, "127.0.0.1:0".parse().unwrap()),
        fixture_sink(),
    )
    .await
    .unwrap();
    let member = start_persistent(
        config(b_seed, "127.0.0.1:0".parse().unwrap()),
        fixture_sink(),
    )
    .await
    .unwrap();
    let next = start_persistent(
        config([0xc3; 32], "127.0.0.1:0".parse().unwrap()),
        fixture_sink(),
    )
    .await
    .unwrap();
    let a_addr = owner.info.primary().unwrap().target.address;
    let b_addr = member.info.primary().unwrap().target.address;
    let id = owner
        .create_channel(name, "owner", 8, crate::channel::ChannelVisibility::Private)
        .await
        .unwrap();
    let request = member.prepare_channel_join("member").await.unwrap();
    let package = member.channel_key_package(request).await.unwrap();
    let welcome = owner.admit_channel(name, &package, "member").await.unwrap();
    member
        .join_channel(
            request,
            name,
            crate::channel::ChannelVisibility::Private,
            &welcome,
        )
        .await
        .unwrap();
    let initial = owner
        .send_channel_text_tracked(name, b"before offline membership")
        .await
        .unwrap();
    assert_eq!(
        wait_text(&member, b"before offline membership").await,
        initial
    );
    wait_ack(&owner, initial).await;
    let b_before = member.export_state().await.unwrap();
    member.shutdown().await;
    let next_request = next.prepare_channel_join("next").await.unwrap();
    let next_package = next.channel_key_package(next_request).await.unwrap();
    owner
        .admit_channel(name, &next_package, "next")
        .await
        .unwrap();
    let a_before = owner.export_state().await.unwrap();
    owner.shutdown().await;
    next.shutdown().await;
    let owner_archive = decode_v2(&a_before, &a_seed).unwrap();
    let membership = owner_archive.channels[0]
        .membership_outbox
        .as_ref()
        .unwrap();
    let commit_id = membership.commit_id;
    let epoch = membership.epoch;
    assert_eq!(
        decode_v2(&b_before, &b_seed).unwrap().channels[0]
            .role
            .epoch()
            + 1,
        epoch
    );
    let a_state = expire_owned(&a_before, &a_seed, name);
    let owner =
        start_persistent_restored(config(a_seed, a_addr), None, fixture_sink(), Some(&a_state))
            .await
            .unwrap();
    // Recreate the actual cold edge: the retained route is still live during
    // restore, but expires before the renewal loop's first roughly 60s pass.
    let mut member_archive = decode_v2(&b_before, &b_seed).unwrap();
    let own = member_archive.channel_routes.get_mut(name).unwrap();
    let local_expiry = now_unix() + 8;
    own.public.data.expiry = local_expiry;
    own.public.control.expiry = local_expiry;
    for alias in &mut own.aliases {
        alias.contact.expiry = local_expiry;
    }
    let b_state = replace_v18_owned_route(&b_before, &b_seed, name, own).unwrap();
    let member =
        start_persistent_restored(config(b_seed, b_addr), None, fixture_sink(), Some(&b_state))
            .await
            .unwrap();
    let result = async {
        let reopened = decode_v2(&member.export_state().await?, &b_seed)?;
        assert_eq!(reopened.channel_routes[name].public, own.public);
        tokio::time::sleep(Duration::from_secs(
            local_expiry.saturating_sub(now_unix()) + 1,
        ))
        .await;
        let current_owner = decode_v2(&owner.export_state().await?, &a_seed)?.channel_routes[name]
            .public
            .clone();
        owner
            .recover_channel_route(name, id, epoch, &welcome, &member.current_info().await?)
            .await?;
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let archive = decode_v2(&owner.export_state().await?, &a_seed)?;
                if archive.channels[0].membership_outbox.is_none() {
                    break Ok::<_, String>(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .map_err(|_| "original member ACK never reached cold owner")??;
        let received = decode_v2(&member.export_state().await?, &b_seed)?;
        let cs = &received.channels[0];
        assert_eq!(cs.role.epoch(), epoch);
        assert_eq!(cs.directory["owner"], current_owner);
        assert_eq!(
            received.channel_routes[name].public, own.public,
            "expired local authority unchanged"
        );
        let (_, target, wire) = cs
            .commit_acks
            .iter()
            .find(|(original, _, _)| *original == commit_id)
            .expect("real original-commit ACK retained");
        assert_eq!(target, &current_owner);
        assert_eq!(crate::channel::mls_epoch_of(wire), Some(epoch));
        let finished = decode_v2(&owner.export_state().await?, &a_seed)?;
        assert_eq!(finished.channels[0].role.epoch(), epoch);
        assert!(finished.channels[0].membership_outbox.is_none());
        Ok::<_, String>(())
    }
    .await;
    owner.shutdown().await;
    member.shutdown().await;
    result.unwrap();
}
