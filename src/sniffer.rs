use crate::models::{
    ApplicationProtocol, IPVersion, PacketInfo, PacketLink, PacketLinkStats, Signaller,
    SniffStatus, TrafficDirection, TransportProtocol,
};
use crate::packet_filtering::PacketFilter;
use crate::sniffed_packet::SniffedPacket;
use crate::utils::format_number_to_bytes;
use chrono::Local;
use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use pcap::{Capture, Device};
use std::collections::HashMap;
use std::io::Write;
use std::io::{BufWriter, stdout};
use std::net::IpAddr;
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

    pub fn start(
        self,
        signaller: Arc<Signaller>,
        packet_info: Arc<PacketInfo>,
        packet_filter: Option<PacketFilter>,
    ) {
        let device_name = self.device.name.as_str();

        // use a smaller buffer so output is printed faster to console
        let mut writer = BufWriter::with_capacity(1024, stdout());
        let mut captured_packets: usize = 0;
        let mut skipped_packets: usize = 0;
        let mut ignored_packets: usize = 0;
        let mut transferred_bytes: u64 = 0;
        let mut received_bytes: u64 = 0;
        let mut packets_sent: usize = 0;
        let mut packets_received: usize = 0;

        let addresses = self
            .device
            .addresses
            .iter()
            .map(|e| e.addr)
            .collect::<Vec<IpAddr>>();

        let mut address_map: HashMap<String, String> = HashMap::new();
        for address in addresses {
            match address {
                IpAddr::V4(address) => {
                    let address = address.to_string();
                    address_map.insert(address.clone(), address);
                }
                IpAddr::V6(x) => {
                    let decimal_dotted_ipv6 = prettify_ip::ipv6_to_decimal_dotted(&x);
                    address_map.insert(decimal_dotted_ipv6, address.to_string());
                }
            }
        }

        let hyphen = format!("{}{}{}\r", "+", "-".repeat(185), "+");
        let header = format!(
            "| {0:^45} | {1:^45} | {2:^9} | {3:^9} | {4:^6} | {5:^11} | {6:^8} | {7:^7} | {8:^19} |\r\n",
            "Source IP",
            "Destination IP",
            "Src Port",
            "Dest Port",
            "IP",
            "Direction",
            "Layer 4",
            "Layer 7",
            "timestamp",
        );
        writeln!(writer, "{}\n{}{}\r", hyphen, header, hyphen);

        loop {
            let mut signal = signaller.mutex.lock().unwrap();
            let mut cap;
            match *signal {
                SniffStatus::RUNNING => {
                    drop(signal);
                    cap = Capture::from_device(device_name)
                        .unwrap()
                        .promisc(true)
                        .snaplen(4000) // we only need the header, we don't need the body
                        .immediate_mode(true)
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
                    if captured_packets != 0 {
                        writer.flush();
                    }
                    writeln!(
                        writer,
                        "Captured Packets: {}\r\nSkipped Packets: {}\r\nBytes Transferred: {}\r\nBytes Received: {}\r\nPackets Sent: {}\r\nPackets Received: {}\r\nSkipped Packets: {}\r",
                        captured_packets,
                        skipped_packets,
                        format_number_to_bytes(transferred_bytes),
                        format_number_to_bytes(received_bytes),
                        packets_sent,
                        packets_received,
                        ignored_packets
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
                    let mut packet_size: usize = packet.header.len as usize;
                    let mut skip = false;
                    let mut traffic_direction = TrafficDirection::OTHER;
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
                                    // skip icmp headers
                                    _ => skip = true,
                                },
                            };
                            // check if  we need to filter out this packet based on port or protocol
                            if let Some(filter) = &packet_filter {
                                if !filter.should_capture_with_ports(src_port, dest_port)
                                    || !filter.should_capture_with_transport(transport_protocol)
                                {
                                    ignored_packets += 1;
                                    continue;
                                }
                            }

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
                                    if address_map.contains_key(&src_ip) {
                                        traffic_direction = TrafficDirection::OUTGOING;
                                    } else if address_map.contains_key(&dest_ip) {
                                        traffic_direction = TrafficDirection::INCOMING;
                                    } else if Self::is_multicast_address(&dest_ip) {
                                        traffic_direction = TrafficDirection::MULTICAST
                                    }
                                    ip_version = IPVersion::IPV4;
                                }
                                NetHeaders::Ipv6(header, _) => {
                                    src_ip = header.source.map(|oct| oct.to_string()).join(".");
                                    dest_ip =
                                        header.destination.map(|oct| oct.to_string()).join(".");

                                    if address_map.contains_key(&src_ip) {
                                        traffic_direction = TrafficDirection::OUTGOING;
                                        src_ip = address_map.get(&src_ip).unwrap().clone();
                                        dest_ip = prettify_ip::parse_ipv6_decimal_dotted(
                                            dest_ip.as_str(),
                                        )
                                        .unwrap()
                                        .to_string();
                                    } else if address_map.contains_key(&dest_ip) {
                                        traffic_direction = TrafficDirection::INCOMING;
                                        dest_ip = address_map.get(&dest_ip).unwrap().clone();
                                        src_ip =
                                            prettify_ip::parse_ipv6_decimal_dotted(src_ip.as_str())
                                                .unwrap()
                                                .to_string();
                                    }

                                    if let TrafficDirection::OTHER = traffic_direction {
                                        dest_ip = prettify_ip::parse_ipv6_decimal_dotted(
                                            dest_ip.as_str(),
                                        )
                                        .unwrap()
                                        .to_string();
                                        src_ip =
                                            prettify_ip::parse_ipv6_decimal_dotted(src_ip.as_str())
                                                .unwrap()
                                                .to_string();
                                        if Self::is_multicast_address(&dest_ip) {
                                            traffic_direction = TrafficDirection::MULTICAST;
                                        }
                                    }

                                    ip_version = IPVersion::IPV6;
                                }
                                // ignore ARP Packets
                                _ => skip = true,
                            };

                            // check if  we need to filter out this packet based on ip
                            if let Some(filter) = &packet_filter {
                                if !filter.should_capture_with_ips(&src_ip, &dest_ip) {
                                    ignored_packets += 1;
                                    continue;
                                }
                            }

                            if skip {
                                skipped_packets += 1;
                                continue;
                            }

                            application_protocol =
                                Self::parse_application_protocol_from_source_and_dest_port(
                                    src_port, dest_port,
                                );
                            captured_packets += 1;

                            match traffic_direction {
                                TrafficDirection::INCOMING | TrafficDirection::MULTICAST => {
                                    received_bytes += packet_size as u64;
                                    packets_received += 1;
                                }
                                _ => {
                                    transferred_bytes += packet_size as u64;
                                    packets_sent += 1
                                }
                            }
                            let sniffed_packet = SniffedPacket::new(
                                src_ip,
                                dest_ip,
                                src_port,
                                dest_port,
                                ip_version,
                                transport_protocol,
                                application_protocol,
                                traffic_direction,
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
                                        packet_size,
                                        1,
                                        now,
                                        now,
                                        sniffed_packet.traffic_direction,
                                        sniffed_packet.ip_version,
                                        application_protocol,
                                    );
                                    info.insert(packet_link, packet_link_stats);
                                    drop(info);
                                }
                                Some(link_stats) => {
                                    link_stats.num_packets += 1;
                                    link_stats.num_bytes += packet_size;
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

    fn is_multicast_address(ip: &str) -> bool {
        if ip.contains(":") {
            // ipv6
            ip.starts_with("ff")
        } else {
            let first_token = ip.split(".").next().unwrap().parse::<u8>().unwrap();
            first_token >= 224 && first_token <= 239
        }
    }
}
