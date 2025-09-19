use crate::models::{
    ApplicationProtocol, IPVersion, PacketInfo, PacketLink, PacketLinkStats, Signaller,
    SniffStatus, TrafficDirection, TransportProtocol,
};
use crate::sniffed_packet::SniffedPacket;
use chrono::Local;
use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use pcap::{Capture, Device};
use std::io::Write;
use std::io::{BufWriter, stdout};
use std::sync::Arc;

/// Sniffer is responsible for capturing packets on a specified network interface.
/// It uses the pcap library to capture packets and etherparse to parse them.
/// It runs in its own thread and checks for pause and stop signals to control the capturing process.
/// It updates shared packet information using a mutex to ensure thread safety.
pub struct Sniffer {
    interface: String,
    device: Device,
}

impl Sniffer {
    pub fn new(interface: String) -> Result<Sniffer, String> {
        let mut adapter_as_device: Option<Device> = None;
        if interface.is_empty() {
            adapter_as_device = Device::lookup().map_err(|e| e.to_string())?;
        } else {
            let devices = Device::list().expect("Could not list devices");
            for device in devices {
                if device.name == interface {
                    adapter_as_device = Some(device);
                    break;
                }
            }
        }
        if adapter_as_device.is_none() {
            Err(format!("Could not find device {}", interface))
        } else {
            Ok(Sniffer {
                interface,
                device: adapter_as_device.unwrap(),
            })
        }
    }

    fn parse_application_protocol_from_source_and_dest_port(
        src_port: u16,
        dest_port: u16,
    ) -> ApplicationProtocol {
        // try to parse application protocol from source and dest port
        let mut app_protocol = Self::parse_application_protocol(dest_port);
        if let ApplicationProtocol::Other = app_protocol {
            app_protocol = Self::parse_application_protocol(src_port)
        }
        app_protocol
    }

    fn parse_application_protocol(port: u16) -> ApplicationProtocol {
        match port {
            20..=21 => ApplicationProtocol::FTP,
            22 => ApplicationProtocol::SSH,
            23 => ApplicationProtocol::Telnet,
            25 => ApplicationProtocol::SMTP,
            53 => ApplicationProtocol::DNS,
            67..=68 => ApplicationProtocol::DHCP,
            69 => ApplicationProtocol::TFTP,
            80 | 8080 => ApplicationProtocol::HTTP,
            109..=110 => ApplicationProtocol::POP,
            123 => ApplicationProtocol::NTP,
            137..=139 => ApplicationProtocol::NetBIOS,
            143 | 220 => ApplicationProtocol::IMAP,
            161..=162 | 199 => ApplicationProtocol::SNMP,
            179 => ApplicationProtocol::BGP,
            389 => ApplicationProtocol::LDAP,
            443 => ApplicationProtocol::HTTPS,
            636 => ApplicationProtocol::LDAPS,
            989..=990 => ApplicationProtocol::FTPS,
            993 => ApplicationProtocol::IMAPS,
            995 => ApplicationProtocol::POP3S,
            1900 => ApplicationProtocol::SSDP,
            5353 => ApplicationProtocol::mDNS,
            _ => ApplicationProtocol::Other,
        }
    }

    pub fn start(self, signaller: Arc<Signaller>, packet_info: Arc<PacketInfo>) {
        let device_name = self.device.name;

        // use a smaller buffer so output is printed faster to console
        let mut writer = BufWriter::with_capacity(1024, stdout());
        let mut captured_packets: usize = 0;
        let mut skipped_packets: usize = 0;

        let legend = "Legend:\r\n\t\
        - S Port : Source Port\r\n\t\
        - D Port : Destination Port\r\n\t\
        - IP     : IP Version (4 or 6)\r\n\t\
        - T P    : Transmission Protocol\r\n\t\
        - A P    : Application Protocol\r\n\n";

        let hyphen = format!("{}{}{}\r", "+", "-".repeat(192), "+");
        let header = format!(
            "| {0:^62} | {1:^62} | {2:^6} | {3:^6} | {4:^5} | {5:^3} | {6:^6} | {7:^19} |\r\n",
            "Source IP", "Destination IP", "S Port", "D Port", "IP", "T P", "A P", "timestamp",
        );
        writeln!(writer, "{}{}\n{}{}\r", legend, hyphen, header, hyphen);

        loop {
            let mut signal = signaller.mutex.lock().unwrap();
            let mut cap;
            match *signal {
                SniffStatus::RUNNING => {
                    drop(signal);
                    cap = Capture::from_device(device_name.as_str())
                        .unwrap()
                        .promisc(true)
                        .immediate_mode(true)
                        .snaplen(4500)
                        .open()
                        .unwrap();
                }
                SniffStatus::PAUSED => {
                    writer.flush().unwrap();
                    while *signal == SniffStatus::PAUSED {
                        signal = signaller.condvar.wait(signal).unwrap();
                    }
                    drop(signal);
                    continue;
                }
                SniffStatus::STOPPED => {
                    writeln!(
                        writer,
                        "Captured Packets: {}\r\nSkipped Packets: {}\r",
                        captured_packets, skipped_packets
                    );
                    drop(signal);
                    break;
                }
            }

            match cap.next_packet() {
                Ok(packet) => {
                    let ts = packet.header.ts;
                    let mut src_ip: String = String::new();
                    let mut dest_ip: String = String::new();
                    let mut src_port: u16 = 0;
                    let mut dest_port: u16 = 0;
                    let mut application_protocol = ApplicationProtocol::Other;
                    let mut transport_protocol = TransportProtocol::Other;
                    let mut timestamp = Local::now();
                    let mut ip_version: IPVersion = IPVersion::IPV4;
                    let mut packet_size: u16 = 0;
                    let mut skip = false;
                    let mut traffic_direction = TrafficDirection::INCOMING;
                    let headers = PacketHeaders::from_ethernet_slice(&packet.data).unwrap();
                    match headers.net {
                        None => continue,
                        Some(netHeaders) => {
                            match headers.transport {
                                None => skip = true,
                                Some(transport) => match transport {
                                    TransportHeader::Udp(h) => {
                                        src_port = h.source_port;
                                        dest_port = h.destination_port;
                                        transport_protocol = TransportProtocol::UDP;
                                    }
                                    TransportHeader::Tcp(h) => {
                                        src_port = h.source_port;
                                        dest_port = h.destination_port;
                                        transport_protocol = TransportProtocol::TCP
                                    }
                                    _ => skip = true,
                                },
                            };

                            if skip {
                                skipped_packets += 1;
                                continue;
                            }

                            match netHeaders {
                                NetHeaders::Ipv4(header, _) => {
                                    //ipV4Header.options
                                    src_ip = header.source.map(|oct| oct.to_string()).join(".");
                                    dest_ip =
                                        header.destination.map(|oct| oct.to_string()).join(".");
                                    ip_version = IPVersion::IPV4;
                                    packet_size = header.total_len
                                }
                                NetHeaders::Ipv6(header, _) => {
                                    src_ip = header.source.map(|oct| oct.to_string()).join(".");
                                    dest_ip =
                                        header.destination.map(|oct| oct.to_string()).join(".");
                                    ip_version = IPVersion::IPV6;
                                    packet_size = header.payload_length
                                }
                                _ => skip = true,
                            };

                            if skip {
                                skipped_packets += 1;
                                continue;
                            }

                            application_protocol =
                                Self::parse_application_protocol_from_source_and_dest_port(
                                    src_port, dest_port,
                                );
                            captured_packets += 1;
                            let sniffed_packet = SniffedPacket::new(
                                src_ip,
                                dest_ip,
                                src_port,
                                dest_port,
                                ip_version,
                                transport_protocol,
                                application_protocol,
                                timestamp,
                            );

                            writeln!(writer, "{}\r", &sniffed_packet);
                            let packet_link = PacketLink::new(
                                sniffed_packet.src_ip,
                                sniffed_packet.dest_ip,
                                sniffed_packet.src_port,
                                sniffed_packet.dest_port,
                                sniffed_packet.transport_protocol,
                            );

                            let mut info = packet_info.packets.lock().unwrap();
                            match info.get_mut(&packet_link) {
                                None => {
                                    // insert new packet link stats
                                    let now = Local::now();
                                    let packet_link_stats = PacketLinkStats::new(
                                        packet_size as usize,
                                        1,
                                        now,
                                        now,
                                        traffic_direction,
                                        sniffed_packet.ip_version,
                                        application_protocol,
                                    );
                                    info.insert(packet_link, packet_link_stats);
                                    drop(info);
                                }
                                Some(link_stats) => {
                                    link_stats.num_packets += 1;
                                    link_stats.num_bytes += packet_size as usize;
                                    link_stats.end_time = Local::now();
                                    drop(info)
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    writeln!(writer, "Could not parse packet: {:?}\r", e);
                }
            }
        }
    }
}
