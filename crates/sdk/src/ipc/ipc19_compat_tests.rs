//! Pin the canonical IPC18 prefix and refuse the two incompatible plain IPC17 dialects.
use super::*;

#[test]
fn ipc19_requests_keep_application18_tags_and_append_channel_management() {
    let cases = [
        (vec![37], Request::PersistProfile, 17),
        (vec![38, 0], Request::RecoverNetwork { urls: vec![] }, 17),
        (
            vec![39, 1],
            Request::ConfigureNetworkDns { enabled: true },
            17,
        ),
        (vec![40], Request::NetworkDnsStatus, 17),
        (vec![41], Request::RuntimeStatus, 17),
        (
            vec![42, 1, b'i'],
            Request::ImportNetworkInvitation {
                invitation: "i".into(),
            },
            17,
        ),
        (
            vec![43, 1, b'x', 1],
            Request::CreateChannelInvitation {
                channel: "x".into(),
                ttl_secs: 1,
            },
            17,
        ),
        (
            vec![44, 1, b'i'],
            Request::InspectChannelInvitation { link: "i".into() },
            17,
        ),
        (
            vec![45, 1, b'i', 1, b'n', 1],
            Request::JoinChannelInvitation {
                link: "i".into(),
                display: "n".into(),
                timeout_secs: 1,
            },
            17,
        ),
        (
            vec![46, 0],
            Request::Sharing(crate::sharing::Request::List),
            18,
        ),
        (vec![47], Request::NetworkStatus, 18),
        (
            vec![48, 1, b'x'],
            Request::ChannelTopic {
                channel: "x".into(),
            },
            19,
        ),
        (
            vec![49, 1, b'x', 0, 1, b't'],
            Request::ChangeChannel {
                channel: "x".into(),
                change: crate::ChannelChange::Topic("t".into()),
            },
            19,
        ),
        (
            vec![49, 1, b'x', 1, 1, b'n'],
            Request::ChangeChannel {
                channel: "x".into(),
                change: crate::ChannelChange::Nickname("n".into()),
            },
            19,
        ),
        (
            vec![49, 1, b'x', 3],
            Request::ChangeChannel {
                channel: "x".into(),
                change: crate::ChannelChange::Leave,
            },
            19,
        ),
        (
            vec![49, 1, b'x', 4],
            Request::ChangeChannel {
                channel: "x".into(),
                change: crate::ChannelChange::Close,
            },
            19,
        ),
    ];
    for (bytes, request, minimum) in cases {
        assert_eq!(postcard::to_allocvec(&request).unwrap(), bytes);
        let (decoded, trailing): (Request, _) = postcard::take_from_bytes(&bytes).unwrap();
        assert!(trailing.is_empty());
        assert_eq!(decoded, request);
        assert_eq!(request.minimum_version(), minimum);
    }
    let mut bytes = vec![49, 1, b'x', 2];
    bytes.extend_from_slice(&[9; 32]);
    assert_eq!(
        postcard::to_allocvec(&Request::ChangeChannel {
            channel: "x".into(),
            change: crate::ChannelChange::Transfer([9; 32])
        })
        .unwrap(),
        bytes
    );
    assert_eq!(
        Request::ChannelTopic {
            channel: "x".into()
        }
        .required_capability(),
        Capability::ChannelMember
    );
    for change in [
        crate::ChannelChange::Topic("t".into()),
        crate::ChannelChange::Transfer([9; 32]),
        crate::ChannelChange::Close,
    ] {
        assert_eq!(
            Request::ChangeChannel {
                channel: "x".into(),
                change
            }
            .required_capability(),
            Capability::ChannelAdmin
        );
    }
    for change in [
        crate::ChannelChange::Nickname("n".into()),
        crate::ChannelChange::Leave,
    ] {
        assert_eq!(
            Request::ChangeChannel {
                channel: "x".into(),
                change
            }
            .required_capability(),
            Capability::ChannelMember
        );
    }
}

#[test]
fn ipc19_responses_keep_application18_wire_and_do_not_reuse_runtime_status() {
    for (bytes, response) in [
        (
            vec![15, 1, 0],
            Response::RuntimeStatus(crate::RuntimeStatus {
                connection: crate::ConnectionState::Connecting,
                relay: crate::RelayState::Disabled,
            }),
        ),
        (
            vec![16, 1, b'i', 1, b'x', 1, 1],
            Response::ChannelInvitation(crate::ChannelInvitation {
                link: "i".into(),
                channel: "x".into(),
                expires_at: 1,
                local_only: true,
            }),
        ),
        (vec![17, 1, b'x'], Response::ChannelJoined("x".into())),
        (
            vec![18, 0, 0, 0, 0, 0, 0],
            Response::NetworkDnsStatus(crate::NetworkNameStatus {
                published: false,
                opted_in: false,
                pending: false,
                removed: false,
                name: None,
                lease_expires_at: None,
            }),
        ),
        (vec![19, 1, b'x'], Response::NetworkRecovered("x".into())),
        (
            vec![20, 1, 0],
            Response::Sharing(crate::sharing::Reply::Piece(vec![])),
        ),
        (
            vec![21, 0, 1, b'n'],
            Response::NetworkStatus(crate::NetworkStatus {
                state: crate::NetworkState::Locked,
                message: "n".into(),
            }),
        ),
        (vec![22, 1, b't'], Response::ChannelTopic("t".into())),
    ] {
        assert_eq!(postcard::to_allocvec(&response).unwrap(), bytes);
        let (decoded, trailing): (Response, _) = postcard::take_from_bytes(&bytes).unwrap();
        assert!(trailing.is_empty());
        assert_eq!(decoded, response);
    }
}

#[cfg(all(any(unix, windows), feature = "ipc", feature = "in-process"))]
mod handshakes {
    use super::*;

    async fn client() -> crate::EmbeddedClient {
        crate::EmbeddedClient::new(
            gcoms_node::node::start(gcoms_node::node::NodeConfig {
                seed: [97; 32],
                listen: "127.0.0.1:0".parse().unwrap(),
                control: None,
                advertise: None,
                inbox_relay: None,
                profile: gcoms_node::node::NodeProfile::fixture(),
                alias_lifecycle: Default::default(),
            })
            .await
            .unwrap(),
        )
    }

    fn hello(version: u16) -> Hello {
        Hello {
            min_version: version,
            max_version: version,
            application: "ipc-compatibility".into(),
            requested_capabilities: vec![
                Capability::IdentityRead,
                Capability::ChannelMember,
                Capability::ChannelAdmin,
                Capability::ProfileAdmin,
            ],
            component: None,
        }
    }

    #[tokio::test]
    async fn both_plain_ipc17_dialects_are_rejected_before_pipelined_requests() {
        let client = client().await;
        // Archived release17 channel-topic/change bytes and main17 lifecycle
        // bytes. Every handshake must fail before any of these is decoded.
        for request in [
            vec![37, 1, b'x'],
            vec![38, 1, b'x', 3],
            vec![37],
            vec![38, 0],
            vec![0xff],
        ] {
            let (mut peer, stream) = tokio::io::duplex(65536);
            write_frame(&mut peer, &Frame::Hello(hello(17)))
                .await
                .unwrap();
            let mut frame = vec![2, 17, 1]; // Frame::Request, version, request ID
            frame.extend(request);
            peer.write_all(&(frame.len() as u32).to_be_bytes())
                .await
                .unwrap();
            peer.write_all(&frame).await.unwrap();
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                serve_connection(
                    stream,
                    client.clone(),
                    hello(19).requested_capabilities,
                    None,
                ),
            )
            .await
            .unwrap();
            assert_eq!(
                result,
                Err(SdkError::Protocol(
                    "ambiguous IPC17; update the client and service together".into()
                ))
            );
            let mut reply = Vec::new();
            peer.read_to_end(&mut reply).await.unwrap();
            assert!(
                reply.is_empty(),
                "no Welcome or dispatched response for ambiguous dialect"
            );
        }
        client.node().shutdown().await;
    }

    #[tokio::test]
    async fn authenticated_profile17_keeps_main_dialect_and_older_versions_refuse_channel19() {
        let client = client().await;
        client
            .create_channel("x", "owner", 4, crate::ChannelVisibility::Private)
            .await
            .unwrap();
        for version in [16, 17, 18, 19] {
            let (mut peer, stream) = tokio::io::duplex(65536);
            let profile = (version == 17).then(|| {
                Arc::new(ProfileAccess {
                    token: [7; 32],
                    inbox: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                })
            });
            let frame = if profile.is_some() {
                Frame::ProfileHello {
                    hello: hello(version),
                    token: [7; 32],
                }
            } else {
                Frame::Hello(hello(version))
            };
            write_frame(&mut peer, &frame).await.unwrap();
            let server = tokio::spawn(serve_profile_connection(
                stream,
                client.clone(),
                hello(19).requested_capabilities,
                None,
                profile,
            ));
            assert!(
                matches!(read_frame(&mut peer).await.unwrap(), Frame::Welcome(welcome) if welcome.version == version)
            );
            // A new enum decoded on an older safe dialect must not execute.
            for (id, request) in [
                (
                    1,
                    Request::ChangeChannel {
                        channel: "x".into(),
                        change: crate::ChannelChange::Topic("new topic".into()),
                    },
                ),
                (
                    2,
                    Request::ChannelTopic {
                        channel: "x".into(),
                    },
                ),
            ] {
                write_frame(
                    &mut peer,
                    &Frame::Request(RequestEnvelope {
                        version,
                        request_id: id,
                        request,
                    }),
                )
                .await
                .unwrap();
                let Frame::Response(response) = read_frame(&mut peer).await.unwrap() else {
                    panic!("response")
                };
                if version < 19 {
                    assert_eq!(response.result, Err(SdkError::PermissionDenied));
                } else if id == 1 {
                    assert!(matches!(response.result, Ok(Response::MessageId(_))));
                } else {
                    assert_eq!(
                        response.result,
                        Ok(Response::ChannelTopic("new topic".into()))
                    );
                }
            }
            assert_eq!(
                client.channel_topic("x").await.unwrap(),
                if version == 19 { "new topic" } else { "" }
            );
            drop(peer);
            assert!(server.await.unwrap().is_err());
        }
        client.node().shutdown().await;
    }
}

#[test]
fn file_reuse_is_ipc20_only_and_existing_file_snapshot_bytes_stay_unchanged() {
    use crate::sharing::{FileInfo, Scope, Status};
    let file = FileInfo {
        id: [1; 16],
        scope: Scope {
            channel: [2; 32],
            participants: vec![],
        },
        name: "a".into(),
        size_bytes: 3,
        verified_bytes: 3,
        status: Status::Complete,
        sources: 1,
        verified_sources: 0,
        completed_by: 0,
        error: None,
    };
    // Independent pre-change field layout, including the next vector element.
    let legacy = (
        [1u8; 16],
        ([2u8; 32], Vec::<[u8; 32]>::new()),
        "a",
        3u64,
        3u64,
        5u32,
        1u16,
        0u16,
        0u16,
        Option::<String>::None,
    );
    let bytes = postcard::to_allocvec(&vec![legacy.clone(), legacy]).unwrap();
    assert_eq!(
        postcard::to_allocvec(&vec![file.clone(), file.clone()]).unwrap(),
        bytes
    );
    assert_eq!(
        postcard::from_bytes::<Vec<FileInfo>>(&bytes).unwrap(),
        vec![file.clone(), file]
    );
    assert_eq!(
        Request::Sharing(crate::sharing::Request::Commit { id: [1; 16] }).minimum_version(),
        18
    );
    let request = Request::Sharing(crate::sharing::Request::CommitReusing { id: [1; 16] });
    assert_eq!(request.minimum_version(), 20);
    assert_eq!(request.required_capability(), Capability::FileSharing);
    let mut expected = vec![46, 11];
    expected.extend_from_slice(&[1; 16]);
    assert_eq!(postcard::to_allocvec(&request).unwrap(), expected);
}
