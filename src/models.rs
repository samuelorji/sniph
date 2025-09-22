use chrono::Local;
use indexmap::IndexMap;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::Ipv4Addr;
use std::ops::Deref;
use std::sync::{Arc, Condvar, Mutex};

/// Enum representing the possible observed values of transport layer protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    /// Transmission Control Protocol
    TCP,
    /// User Datagram Protocol
    UDP,
    /// Unknown Protocol
    Other,
}

impl fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = format!("{:?}", self);
        f.pad(&s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IPVersion {
    IPV4,
    IPV6,
}

impl fmt::Display for IPVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = format!("{:?}", self);
        f.pad(&s)
    }
}

/// Enum representing the possible observed values of application layer protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApplicationProtocol {
    /// File Transfer Protocol
    FTP,
    /// Secure Shell
    SSH,
    /// Telnet
    Telnet,
    /// Simple Mail Transfer Protocol
    SMTP,
    /// Domain Name System
    DNS,
    /// Dynamic Host Configuration Protocol
    DHCP,
    /// Trivial File Transfer Protocol
    TFTP,
    /// Hypertext Transfer Protocol
    HTTP,
    /// Post Office Protocol
    POP,
    /// Network Time Protocol
    NTP,
    /// NetBIOS
    NetBIOS,
    /// Post Office Protocol 3 over TLS/SSL
    POP3S,
    /// Internet Message Access Protocol
    IMAP,
    /// Simple Network Management Protocol
    SNMP,
    /// Border Gateway Protocol
    BGP,
    /// Lightweight Directory Access Protocol
    LDAP,
    ///Hypertext Transfer Protocol over TLS/SSL
    HTTPS,
    /// Lightweight Directory Access Protocol over TLS/SSL
    LDAPS,
    /// File Transfer Protocol over TLS/SSL
    FTPS,
    ///Internet Message Access Protocol over TLS/SSL
    IMAPS,
    /// Simple Service Discovery Protocol
    SSDP,
    /// Extensible Messaging and Presence Protocol
    XMPP,
    /// Multicast DNS
    #[allow(non_camel_case_types)]
    mDNS,
    /// not identified
    Other,
}

impl fmt::Display for ApplicationProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = format!("{:?}", self);
        f.pad(&s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SniffStatus {
    RUNNING,
    PAUSED,
    STOPPED,
}

pub struct Signaller {
    pub mutex: Mutex<SniffStatus>,
    pub condvar: Condvar,
}

impl Signaller {
    pub fn new(mutex: Mutex<SniffStatus>, condvar: Condvar) -> Signaller {
        Signaller { mutex, condvar }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TrafficDirection {
    INCOMING,
    OUTGOING,
    MULTICAST,
    OTHER,
}

impl fmt::Display for TrafficDirection {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let s = format!("{:?}", self);
        f.pad(&s)
    }
}
#[derive(Hash, PartialEq, Eq)]
pub struct PacketLink {
    pub src_ip: IP,
    pub dest_ip: IP,
    pub src_port: u16,
    pub dest_port: u16,
    pub transport_protocol: TransportProtocol,
}

impl PacketLink {
    pub fn new(
        src_ip: IP,
        dest_ip: IP,
        src_port: u16,
        dest_port: u16,
        transport_protocol: TransportProtocol,
    ) -> PacketLink {
        PacketLink {
            src_ip,
            dest_ip,
            src_port,
            dest_port,
            transport_protocol,
        }
    }
}

pub struct PacketLinkStats {
    pub num_bytes: u128,
    pub num_packets: u128,
    pub start_time: chrono::DateTime<Local>,
    pub end_time: chrono::DateTime<Local>,
    pub traffic_direction: TrafficDirection,
    pub ip_version: IPVersion,
    pub application_protocol: ApplicationProtocol,
}

impl PacketLinkStats {
    pub fn new(
        num_bytes: u128,
        num_packets: u128,
        start_time: chrono::DateTime<Local>,
        end_time: chrono::DateTime<Local>,
        traffic_direction: TrafficDirection,
        ip_version: IPVersion,
        application_protocol: ApplicationProtocol,
    ) -> PacketLinkStats {
        PacketLinkStats {
            num_bytes,
            num_packets,
            start_time,
            end_time,
            traffic_direction,
            ip_version,
            application_protocol,
        }
    }
}

pub struct PacketStatistics {
    pub captured_packets: u128,
    pub skipped_packets: u128,
    pub filtered_packets: u128,
    pub transferred_bytes: u128,
    pub received_bytes: u128,
    pub packets_sent: u128,
    pub packets_received: u128,
}
impl PacketStatistics {
    pub fn new() -> PacketStatistics {
        PacketStatistics {
            captured_packets: 0,
            skipped_packets: 0,
            filtered_packets: 0,
            transferred_bytes: 0,
            received_bytes: 0,
            packets_sent: 0,
            packets_received: 0,
        }
    }
}
pub struct PacketInfo {
    pub stats: PacketStatistics,
    pub packet_mapping: IndexMap<PacketLink, PacketLinkStats>,
}

impl PacketInfo {
    pub fn new() -> Self {
        PacketInfo {
            stats: PacketStatistics::new(),
            packet_mapping: IndexMap::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReporterStatus {
    RUNNING,
    STOPPED,
}
pub struct ReporterSignaller {
    pub mutex: Mutex<ReporterStatus>,
    pub condvar: Condvar,
}

impl ReporterSignaller {
    pub fn new() -> Self {
        ReporterSignaller {
            mutex: Mutex::new(ReporterStatus::RUNNING),
            condvar: Condvar::new(),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum IP {
    CACHED(Arc<str>),
    UNCACHED(String),
}

impl Display for IP {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            IP::CACHED(r) => f.pad(&r),
            IP::UNCACHED(s) => f.pad(s),
        }
    }
}

impl Deref for IP {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        match self {
            IP::CACHED(s) => &s,
            IP::UNCACHED(s) => &s,
        }
    }
}
#[derive(Debug, Hash, PartialEq, Eq)]
pub enum IPOctet {
    V4([u8; 4]),
    V6([u8; 16]),
}
