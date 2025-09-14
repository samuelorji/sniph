use std::fmt;

/// Enum representing the possible observed values of transport layer protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    /// Transmission Control Protocol
    TCP,
    /// User Datagram Protocol
    UDP,
    /// Unknown Protocol
    Other
}


impl fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IPVersion {
    IPV4,
    IPV6
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
    Other
}

impl fmt::Display for ApplicationProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = format!("{:?}", self);
        f.pad(&s)
    }
}