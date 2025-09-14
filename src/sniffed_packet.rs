use std::fmt::{format, Display, Formatter};
use std::time::Instant;
use crate::models::{ApplicationProtocol, IPVersion, TransportProtocol};
use chrono::Local;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniffedPacket {
    src_ip : String,
    dest_ip : String,
    src_port : u16,
    dest_port : u16,
    ip_version : IPVersion,
    transport_protocol : TransportProtocol,
    application_protocol : ApplicationProtocol,
    timestamp: chrono::DateTime<Local>,
}

impl SniffedPacket {
    pub fn new(src_ip : String, dest_ip : String, src_port : u16, dest_port: u16,ip_version: IPVersion, transport_protocol: TransportProtocol, application_protocol: ApplicationProtocol, timestamp : chrono::DateTime<Local>) -> SniffedPacket {
        SniffedPacket {
            src_ip,
            dest_ip,
            src_port,
            dest_port,
            ip_version,
            transport_protocol,
            application_protocol,
            timestamp,
        }
    }
}

impl Display for SniffedPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let hyphen = format!("{}{}{}","+","-".repeat(192), "+");
        let msg = format!(
                "| {0:^62} | {1:^62} | {2:^6} | {3:^6} | {4:^5} | {5:^8} | {6:^6} | {7:^18} |\n{8}",
                self.src_ip,
                self.dest_ip,
                self.src_port,
                self.dest_port,
                self.ip_version,
                self.transport_protocol,
                self.application_protocol,
                self.timestamp.format("%Y-%m-%d %H:%M:%S"),
                hyphen,
        );
        write!(f,"{}", msg)
    }
}