use crate::models::{ApplicationProtocol, IPVersion, TrafficDirection, TransportProtocol};
use chrono::Local;
use std::fmt::{Display, Formatter, format};
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniffedPacket {
    pub src_ip: String,
    pub dest_ip: String,
    pub src_port: u16,
    pub dest_port: u16,
    pub ip_version: IPVersion,
    pub transport_protocol: TransportProtocol,
    application_protocol: ApplicationProtocol,
    pub traffic_direction: TrafficDirection,
    timestamp: chrono::DateTime<Local>,
}

impl SniffedPacket {
    pub fn new(
        src_ip: String,
        dest_ip: String,
        src_port: u16,
        dest_port: u16,
        ip_version: IPVersion,
        transport_protocol: TransportProtocol,
        application_protocol: ApplicationProtocol,
        traffic_direction: TrafficDirection,
        timestamp: chrono::DateTime<Local>,
    ) -> SniffedPacket {
        SniffedPacket {
            src_ip,
            dest_ip,
            src_port,
            dest_port,
            ip_version,
            transport_protocol,
            application_protocol,
            traffic_direction,
            timestamp,
        }
    }
}

impl Display for SniffedPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let hyphen = format!("{}{}{}", "+", "-".repeat(185), "+");
        let msg = format!(
            "| {0:^45} | {1:^45} | {2:^9} | {3:^9} | {4:^6} | {5:^11} | {6:^8} | {7:^7} | {8:^19} |\r\n{9}",
            self.src_ip,
            self.dest_ip,
            self.src_port,
            self.dest_port,
            self.ip_version,
            self.traffic_direction,
            self.transport_protocol,
            self.application_protocol,
            self.timestamp.format("%Y-%m-%d %H:%M:%S"),
            hyphen,
        );
        write!(f, "{}\r", msg)
    }
}
