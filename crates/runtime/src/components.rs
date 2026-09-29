//! Optional host services. The protocol library contains no shell or installer.
use async_trait::async_trait;
use gcoms_sdk::{files, shell, SdkError};

/// Implemented by a trusted host. Remote callers reach these methods only through
/// authenticated, capability-checked component IPC. Implementations must also
/// enforce their registered component identities and own all background workers.
#[async_trait]
pub trait ComponentServices: Send + Sync {
    async fn shell(
        &self,
        component: [u8; 16],
        request: shell::ShellRequest,
    ) -> Result<shell::ShellReply, SdkError>;

    async fn files(
        &self,
        component: [u8; 16],
        request: files::FileRequest,
    ) -> Result<files::FileReply, SdkError>;

    /// Stop and join workers before the runtime releases its profile and node.
    async fn shutdown(&self);
}

#[cfg(all(test, feature = "relay-host"))]
mod tests {
    use super::*;
    use crate::{store::ProtocolStore, ProtocolRuntime, RuntimeOptions};
    use gcoms_sdk::{CarrierProfile, GcClient};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::sync::Notify;

    #[derive(Default)]
    struct Service {
        entered: Notify,
        release: Notify,
        stopped: AtomicUsize,
    }
    #[async_trait]
    impl ComponentServices for Service {
        async fn shell(
            &self,
            component: [u8; 16],
            _: shell::ShellRequest,
        ) -> Result<shell::ShellReply, SdkError> {
            assert_eq!(component, [42; 16]);
            self.entered.notify_one();
            self.release.notified().await;
            Ok(shell::ShellReply::Health {
                ready: true,
                shell: "fixture".into(),
                running: 0,
                error: None,
            })
        }
        async fn files(
            &self,
            _: [u8; 16],
            _: files::FileRequest,
        ) -> Result<files::FileReply, SdkError> {
            Err(SdkError::PermissionDenied)
        }
        async fn shutdown(&self) {
            self.stopped.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn host_services_default_deny_install_once_and_drain_before_shutdown() {
        let root = tempfile::tempdir().unwrap();
        crate::private_fs::make_private(root.path(), true).unwrap();
        let (store, data) = ProtocolStore::create(&root.path().join("profile"), "fixture").unwrap();
        let runtime = ProtocolRuntime::from_storage(
            Arc::new(store),
            data,
            RuntimeOptions {
                durable_channel_inbox: false,
                listen: "127.0.0.1:0".parse().unwrap(),
                advertise: None,
                relay: None,
                fixture: true,
                carrier: CarrierProfile::Legacy,
                network: None,
            },
        )
        .await
        .unwrap();
        let client = runtime.sdk_client();
        assert!(matches!(
            client
                .component_shell([42; 16], shell::ShellRequest::Health)
                .await,
            Err(SdkError::PermissionDenied)
        ));
        let service = Arc::new(Service::default());
        runtime
            .install_component_services(service.clone())
            .await
            .unwrap();
        assert!(runtime
            .install_component_services(Arc::new(Service::default()))
            .await
            .is_err());
        let caller = client.clone();
        let request = tokio::spawn(async move {
            caller
                .component_shell([42; 16], shell::ShellRequest::Health)
                .await
        });
        service.entered.notified().await;
        let closing = runtime.clone();
        let shutdown = tokio::spawn(async move { closing.shutdown().await });
        tokio::task::yield_now().await;
        assert!(!shutdown.is_finished());
        assert_eq!(service.stopped.load(Ordering::SeqCst), 0);
        service.release.notify_one();
        request.await.unwrap().unwrap();
        shutdown.await.unwrap().unwrap();
        assert_eq!(service.stopped.load(Ordering::SeqCst), 1);
        assert!(matches!(
            client
                .component_shell([42; 16], shell::ShellRequest::Health)
                .await,
            Err(SdkError::ConnectionClosed)
        ));
        assert!(matches!(
            runtime
                .install_component_services(Arc::new(Service::default()))
                .await,
            Err(SdkError::ConnectionClosed)
        ));
    }
}
