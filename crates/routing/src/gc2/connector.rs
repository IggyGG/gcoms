//! Terminal acquisition through an already connected GC/2 entry. Route selection
//! and entry lifetime belong to the runtime; this adapter never dials an entry.
use super::{entry::EntryCarrier, transit::TransitDescriptor};
use crate::wire::Target;
use gcoms_core::TrafficClass;
use gcoms_transport::connector::{ConnectFuture, Connector};
use std::net::SocketAddr;

pub struct PreparedConnector {
    entry: EntryCarrier,
    middle: TransitDescriptor,
}

impl PreparedConnector {
    pub fn new(entry: EntryCarrier, middle: TransitDescriptor) -> Self {
        Self { entry, middle }
    }
}

impl Connector for PreparedConnector {
    fn binds_traffic_class(&self) -> bool {
        true
    }

    fn connect(&self, addr: SocketAddr, service_id: [u8; 32]) -> ConnectFuture<'_> {
        self.connect_with_class_excluding(addr, service_id, &[], TrafficClass::Interactive)
    }

    fn connect_excluding<'a>(
        &'a self,
        addr: SocketAddr,
        service_id: [u8; 32],
        excluded: &'a [(SocketAddr, [u8; 32])],
    ) -> ConnectFuture<'a> {
        self.connect_with_class_excluding(addr, service_id, excluded, TrafficClass::Interactive)
    }

    fn connect_with_class_excluding<'a>(
        &'a self,
        addr: SocketAddr,
        service_id: [u8; 32],
        excluded: &'a [(SocketAddr, [u8; 32])],
        class: TrafficClass,
    ) -> ConnectFuture<'a> {
        Box::pin(async move {
            self.entry
                .connect_via(
                    class,
                    &self.middle,
                    &Target::Relay { addr, service_id },
                    excluded,
                )
                .await
        })
    }
}
