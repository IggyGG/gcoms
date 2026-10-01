use gcoms_channel_service::{ChannelLog, Error, Limits};
use gcoms_crypto::IdentityKeypair;
use gcoms_mls::hosted::{HostedSession, JoinPermit, PreparedHostedJoin, HOSTED_GENESIS_EPOCH};
use std::io::{Seek, SeekFrom, Write};

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    gcoms_private_fs::make_private(dir.path(), true).unwrap();
    dir
}

fn limits() -> Limits {
    Limits {
        bytes: 128 * 1024 * 1024,
        records: 1000,
    }
}

#[test]
fn ordered_ciphertext_survives_restart_and_offline_owner() {
    let dir = private_dir();
    let path = dir.path().join("channel.log");
    let root = IdentityKeypair::from_seed([57; 32]);
    let mut owner = HostedSession::create(&root, "owner", 64, true).unwrap();
    let channel = owner.policy().channel_id();
    let mut log = ChannelLog::create(
        &path,
        owner.policy().clone(),
        channel,
        &owner.export_group_info().unwrap(),
        limits(),
    )
    .unwrap();
    assert!(matches!(
        ChannelLog::open(&path, channel, limits()),
        Err(Error::Busy)
    ));
    let (mut alice, first) = PreparedHostedJoin::new("alice")
        .unwrap()
        .join(log.observer(), &JoinPermit::public(), 100)
        .unwrap();
    let join = log
        .append_join(&first, alice.proposed_group_info().unwrap(), 100)
        .unwrap();
    assert_eq!(join.sequence, 1);
    alice.accept_join(&first).unwrap();
    let message = alice
        .send_hosted(b"owner is offline, but this is retained")
        .unwrap();
    let accepted = log.append_message(&message, 101).unwrap();
    assert_eq!(accepted.sequence, 2);
    let (mut bob, second) = PreparedHostedJoin::new("bob")
        .unwrap()
        .join(log.observer(), &JoinPermit::public(), 102)
        .unwrap();
    log.append_join(&second, bob.proposed_group_info().unwrap(), 102)
        .unwrap();
    bob.accept_join(&second).unwrap();
    assert_eq!(
        owner.epoch(),
        HOSTED_GENESIS_EPOCH,
        "no existing recipient ACK was needed"
    );
    drop(log);
    let mut log = ChannelLog::open(&path, channel, limits()).unwrap();
    assert_eq!(log.len(), 3);
    assert_eq!(log.observer().epoch(), HOSTED_GENESIS_EPOCH + 2);
    assert_eq!(
        log.append_message(&message, 103).unwrap(),
        accepted,
        "exact retry returns original acceptance across epochs/restarts"
    );
    let first_record = log.read(1).unwrap().unwrap();
    let (commit, _) = first_record.membership().unwrap();
    owner.receive(commit, first_record.accepted_at).unwrap();
    let app = log.read(2).unwrap().unwrap().message().unwrap().unwrap();
    assert_eq!(
        owner.receive_hosted(&app).unwrap(),
        b"owner is offline, but this is retained"
    );
    let last = log.read(3).unwrap().unwrap();
    owner
        .receive(last.membership().unwrap().0, last.accepted_at)
        .unwrap();
    assert_eq!(owner.roster(), bob.roster());
    let reply = owner.send_hosted(b"caught up").unwrap();
    log.append_message(&reply, 104).unwrap();
    assert_eq!(bob.receive_hosted(&reply).unwrap(), b"caught up");
    drop(log);
    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.windows(16).any(|w| w == b"owner is offline"));
    assert!(!bytes.windows(32).any(|w| w == [57; 32]));
    let mut log = ChannelLog::open(&path, channel, limits()).unwrap();
    assert!(log.read(0).unwrap().is_none());
    assert!(log.read(u64::MAX).unwrap().is_none());
}

#[test]
fn torn_tail_is_recovered_but_complete_corruption_is_not_discarded() {
    let dir = private_dir();
    let path = dir.path().join("channel.log");
    let root = IdentityKeypair::from_seed([58; 32]);
    let mut owner = HostedSession::create(&root, "owner", 64, true).unwrap();
    let channel = owner.policy().channel_id();
    let mut log = ChannelLog::create(
        &path,
        owner.policy().clone(),
        channel,
        &owner.export_group_info().unwrap(),
        limits(),
    )
    .unwrap();
    let message = owner.send_hosted(b"durable").unwrap();
    let receipt = log.append_message(&message, 100).unwrap();
    drop(log);
    let committed = std::fs::metadata(&path).unwrap().len();
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    file.write_all(&[0, 0, 0, 10, 1, 2, 3]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let mut log = ChannelLog::open(&path, channel, limits()).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), committed);
    assert_eq!(log.append_message(&message, 101).unwrap(), receipt);
    drop(log);
    let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    file.write_all(&[0x99]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    // Ensure corruption even in the unlikely event the original byte was 0x99.
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[committed as usize - 2] ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    assert!(ChannelLog::open(&path, channel, limits()).is_err());
    assert_eq!(std::fs::metadata(&path).unwrap().len(), committed);
}

#[test]
fn invalid_join_and_quota_refusals_preserve_accepted_prefix() {
    let dir = private_dir();
    let path = dir.path().join("channel.log");
    let root = IdentityKeypair::from_seed([59; 32]);
    let mut owner = HostedSession::create(&root, "owner", 2, true).unwrap();
    let channel = owner.policy().channel_id();
    let limit = Limits {
        records: 1,
        ..limits()
    };
    let mut log = ChannelLog::create(
        &path,
        owner.policy().clone(),
        channel,
        &owner.export_group_info().unwrap(),
        limit,
    )
    .unwrap();
    let (alice, first) = PreparedHostedJoin::new("alice")
        .unwrap()
        .join(log.observer(), &JoinPermit::public(), 100)
        .unwrap();
    drop(log);
    let before = std::fs::read(&path).unwrap();
    let mut log = ChannelLog::open(&path, channel, limit).unwrap();
    assert!(log
        .append_join(&first, &owner.export_group_info().unwrap(), 100)
        .is_err());
    drop(log);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let mut log = ChannelLog::open(&path, channel, limit).unwrap();
    let msg = owner.send_hosted(b"fills record quota").unwrap();
    let receipt = log.append_message(&msg, 100).unwrap();
    drop(log);
    let before = std::fs::read(&path).unwrap();
    let mut log = ChannelLog::open(&path, channel, limit).unwrap();
    assert!(matches!(
        log.append_join(&first, alice.proposed_group_info().unwrap(), 101),
        Err(Error::Full)
    ));
    assert_eq!(log.observer().epoch(), HOSTED_GENESIS_EPOCH);
    drop(log);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let mut log = ChannelLog::open(&path, channel, limit).unwrap();
    assert_eq!(log.append_message(&msg, 101).unwrap(), receipt);
}
