//! Late-bound GC/2 role gate for a listener that may later act as a relay.
//!
//! The listener is built before owner provisioning creates the relay service,
//! so the gate is resolved per connection: until this node provides a relay
//! service every path passes through unchanged, and afterwards the capability
//! gate fixes entry, transit, control or terminal before any registered
//! endpoint can run. The gate never falls back to GC/1 within a connection.
#![cfg(feature = "experimental-gc2")]

use super::routing::RoutingRuntime;
use gcoms_transport::server::{Dispatch, DispatchHandlerFactory, DuplexHandler};
use std::sync::Arc;

pub(crate) fn dispatch_factory(
    runtime: Option<Arc<RoutingRuntime>>,
    terminal: Option<DuplexHandler>,
) -> DispatchHandlerFactory {
    Arc::new(move || {
        let service = runtime.as_ref().and_then(|runtime| {
            runtime
                .service
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
        });
        match service {
            Some(service) => match terminal.clone() {
                Some(terminal) => service.gc2_handler_factory_with_terminal(terminal)(),
                None => service.gc2_handler_factory()(),
            },
            None => Arc::new(|_path: &str, _registered: bool| Dispatch::Pass),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::RoutingConfig;
    use gcoms_routing::service::{RelayService, ServicePolicy};
    use gcoms_routing::Directory;

    fn runtime() -> Arc<RoutingRuntime> {
        RoutingRuntime::new(RoutingConfig::default(), Directory::new(), true).unwrap()
    }

    #[test]
    fn gate_passes_every_path_until_a_relay_service_is_provisioned() {
        let factory = dispatch_factory(Some(runtime()), None);
        let handler = factory();
        assert!(matches!(handler("unknown", false), Dispatch::Pass));
        assert!(matches!(handler("registered", true), Dispatch::Pass));
    }

    #[test]
    fn gate_rejects_unknown_paths_once_a_relay_service_exists() {
        let runtime = runtime();
        let directory = Arc::new(Directory::new());
        let service = RelayService::new(
            "127.0.0.1:443".parse().unwrap(),
            [9; 32],
            [7; 32],
            directory,
            ServicePolicy::default(),
        )
        .unwrap();
        *runtime.service.lock().unwrap_or_else(|p| p.into_inner()) = Some(service);
        let factory = dispatch_factory(Some(runtime), None);
        let handler = factory();
        assert!(matches!(
            handler("not-a-capability", false),
            Dispatch::Rejected
        ));
        // A registered private path still passes to its normal envelope checks.
        assert!(matches!(handler("registered", true), Dispatch::Pass));
    }

    #[test]
    fn gate_without_a_runtime_is_a_pass_through() {
        let factory = dispatch_factory(None, None);
        let handler = factory();
        assert!(matches!(handler("unknown", false), Dispatch::Pass));
    }
}
