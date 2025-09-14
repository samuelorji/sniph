mod sniffed_packet;
mod sniffer;
mod models;
mod sniff_details;

use std::fmt::format;
use std::io::{BufWriter, Write};
use std::sync::{Arc, Mutex};
use clap::Parser;
use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use pcap::{Device, Capture, Error, Packet};
use crate::sniffer::Sniffer;

/// Packet Sniffing Program
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Print devices on system and exits
    #[arg(short, long = "devices")]
    devices: bool,

    /// interface to sniff on
    #[arg(short, long)]
    interface: String,
}

fn main() {
    let args = Args::parse();
    if args.devices {
        print_devices();
        std::process::exit(0);
    }


    let mut sniff_stats = sniff_details::SniffStats::new();

    let stats = Arc::new(Mutex::new(sniff_stats));
    
    let sniffer_stats = stats.clone();
    // ctrlc::set_handler(move || {
    //     let ctcl_c_stats = stats.clone();
    //     let sniff_stats = ctcl_c_stats.lock().unwrap();
    //     let captured = sniff_stats.get_packets_captured();
    //     let skipped = sniff_stats.get_packets_skipped();
    //
    //     println!("\nCaptured Packets:{}\nSkipped:{}\n", captured, skipped);
    //     std::process::exit(1);
    //     ()
    // });

    match sniffer::Sniffer::new(args.interface) {
        Ok(sniffer) => {
            sniffer.start(sniffer_stats);
        }
        Err(e) => {
            eprintln!("Sniffer Error:\n{}", e);
            std::process::exit(1);
        }
    }


    // listen_on_adapter(&args.adapter)
}

fn print_devices() {
    const DEVICE_COLUMN_WIDTH: usize = 20;
    const ADDRESS_COLUMN_WIDTH: usize = 50;

    let devices = pcap::Device::list().expect("Could not list devices");

    let mut writer = BufWriter::new(std::io::stdout());
    let hyphen_line = format!("{}{}{}", "+", "-".repeat(74_usize), "+");

    writer.write_all(format!("{}\n", hyphen_line).as_bytes()).unwrap();
    writer.write_all(format!(
        "| {0: <DEVICE_COLUMN_WIDTH$} | {1: <ADDRESS_COLUMN_WIDTH$}|\n",
        "Device Name", "Addresses", DEVICE_COLUMN_WIDTH = DEVICE_COLUMN_WIDTH, ADDRESS_COLUMN_WIDTH = ADDRESS_COLUMN_WIDTH
    ).as_bytes()).unwrap();
    writer.write_all(format!("{}\n", hyphen_line).as_bytes()).unwrap();
    for device in devices.iter() {
        if device.addresses.is_empty() {
            writer.write_all(format!("| {0: <DEVICE_COLUMN_WIDTH$} | {1: <ADDRESS_COLUMN_WIDTH$}|\n", &device.name, "", DEVICE_COLUMN_WIDTH = DEVICE_COLUMN_WIDTH, ADDRESS_COLUMN_WIDTH = ADDRESS_COLUMN_WIDTH).as_bytes()).unwrap();
            writer.write_all(format!("{}\n", hyphen_line).as_bytes()).unwrap();
        } else {
            let mut name_written = false;
            for address in device.addresses.iter() {
                let name = if name_written {
                    ""
                } else {
                    &device.name
                };
                writer.write_all(format!("| {0: <DEVICE_COLUMN_WIDTH$} | {1: <ADDRESS_COLUMN_WIDTH$}|\n", name, address.addr.to_string(), DEVICE_COLUMN_WIDTH = DEVICE_COLUMN_WIDTH, ADDRESS_COLUMN_WIDTH = ADDRESS_COLUMN_WIDTH).as_bytes()).unwrap();
                name_written = true
            }
            writer.write_all(format!("{}\n", hyphen_line).as_bytes()).unwrap();
        }
    }
}

fn listen_on_adapter(adapter_name: &str) {
    let devices = Device::list().expect("Could not list devices");
    let mut adapter_as_device : Option<Device> = None;

    for device in devices {
        if device.name == adapter_name {
            adapter_as_device = Some(device);
            break;
        }
    }

    if adapter_as_device.is_none() {
        eprintln!("Could not find device {}", adapter_name);
    }

    let device = adapter_as_device.unwrap();
    //let device = devices.iter().find(|device| device.name == *adapter_name).expect(format!("Could not find device with name {}", adapter_name).as_str()).clone();
    //let device = Device::try_from(adapter_name).unwrap();
    let mut cap = Capture::from_device(device).unwrap()
        .promisc(true)
        .immediate_mode(true)
        .snaplen(5000)
        .open()
        .unwrap();


    println!("adapter name is {}", &adapter_name);
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                //println!("packet timestamp is {:?}", packet.header.);
                let headers = PacketHeaders::from_ethernet_slice(&packet.data).unwrap();
                match headers.net {
                    None => continue,
                    Some(netHeaders) => {
                        let (src_port, dest_port)  = match headers.transport {
                            None => {
                                println!("No transport headers found");
                                continue
                            },
                            Some(transport) => {
                                match transport {
                                    TransportHeader::Udp(h) => {
                                        (h.source_port, h.destination_port)
                                    },
                                    TransportHeader::Tcp(head) => (head.source_port, head.destination_port),
                                    _ => {
                                        println!("unwanted transport header");
                                        continue
                                    },
                                }
                            }
                        };

                        let (src_ip, dest_ip) = match netHeaders {
                            NetHeaders::Ipv4(ipV4Header, _) => {
                                let src_ip = ipV4Header.source.map(|oct| oct.to_string()).join(".");
                                let dest_ip = ipV4Header.destination.map(|oct| oct.to_string()).join(".");
                                (src_ip, dest_ip)
                            }
                            NetHeaders::Ipv6(header, _) => {
                                let src_ip = header.source.map(|oct| oct.to_string()).join(".");
                                let dest_ip = header.destination.map(|oct| oct.to_string()).join(".");
                                (src_ip, dest_ip)
                            }
                            _ =>  {
                                println!("unwanted net header");
                                continue
                            }
                        };
                        println!("{}:{} > {}:{}", src_ip, src_port, dest_ip, dest_port);
                    }
                }

            }
            Err(e) => {
                println!("Could not parse packet: {:?}", e);
            }
        }
    }

    /* TODO
    1. Output basic Sniffed Packet to terminal
    2. capture input from user to pause or resume sniffing

    */
}
