use std::fmt::format;
use std::io::{BufWriter, Write};
use clap::Parser;

/// Packet Sniffing Program
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Print devices on system and exits
    #[arg(short, long = "devices")]
    devices: bool,
}

fn main() {
    let args = Args::parse();
    if args.devices {
        print_devices();
        std::process::exit(0);
    }
}

fn print_devices(){
    const DEVICE_COLUMN_WIDTH : usize = 20;
    const ADDRESS_COLUMN_WIDTH : usize = 50;

    let devices = pcap::Device::list().expect("Could not list devices");

    let mut writer = BufWriter::new(std::io::stdout());
    let hyphen_line = format!("{}{}{}", "+","-".repeat(74_usize) ,"+");

    writer.write_all(format!("{}\n", hyphen_line).as_bytes()).unwrap();
    writer.write_all( format!(
        "| {0: <DEVICE_COLUMN_WIDTH$} | {1: <ADDRESS_COLUMN_WIDTH$}|\n",
        "Device Name", "Addresses", DEVICE_COLUMN_WIDTH = DEVICE_COLUMN_WIDTH, ADDRESS_COLUMN_WIDTH = ADDRESS_COLUMN_WIDTH
    ).as_bytes()).unwrap();
    writer.write_all(format!("{}\n", hyphen_line).as_bytes()).unwrap();
    for device in devices.iter() {
        if device.addresses.is_empty() {
            writer.write_all(format!("| {0: <DEVICE_COLUMN_WIDTH$} | {1: <ADDRESS_COLUMN_WIDTH$}|\n", &device.name,"",DEVICE_COLUMN_WIDTH = DEVICE_COLUMN_WIDTH, ADDRESS_COLUMN_WIDTH = ADDRESS_COLUMN_WIDTH).as_bytes()).unwrap();
            writer.write_all(format!("{}\n", hyphen_line).as_bytes()).unwrap();
        } else {
            let mut name_written = false;
            for address in device.addresses.iter() {
                let name = if name_written {
                    ""
                } else {
                    &device.name
                };
                writer.write_all(format!("| {0: <DEVICE_COLUMN_WIDTH$} | {1: <ADDRESS_COLUMN_WIDTH$}|\n", name,address.addr.to_string(), DEVICE_COLUMN_WIDTH = DEVICE_COLUMN_WIDTH, ADDRESS_COLUMN_WIDTH = ADDRESS_COLUMN_WIDTH).as_bytes()).unwrap();
                name_written = true
            }
            writer.write_all(format!("{}\n", hyphen_line).as_bytes()).unwrap();
        }
    }
}
