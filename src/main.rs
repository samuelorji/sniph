mod models;
mod packet_filtering;
mod reporter;
mod sniffed_packet;
mod sniffer;
mod utils;

use crate::models::{IP, PacketInfo, ReporterSignaller, ReporterStatus, Signaller, SniffStatus};
use crate::packet_filtering::PacketFilter;
use crate::reporter::Reporter;
use crate::sniffer::Sniffer;
use clap::Parser;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers, read};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use pcap::{Capture, Device, Error, Packet};
use std::cmp::Ord;
use std::fmt::format;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

/// Simple and intuitive Packet Sniffing Program
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Prints devices or interfaces found on system and exits
    #[arg(short, long)]
    devices: bool,

    /// interface to sniff on. Will exit with an error if the interface cannot be found
    #[arg(short, long)]
    interface: Option<String>,

    /// Optional output folder where report will be written to. If no output is specified, no report is written
    /// output will be a folder with name report_YYYY_MM_DD_H_M_S containing a report in csv and 2 SVG files showing data and packet throughput
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// size of print buffer, if set to 0, packets will be printed to stdout immediately.
    /// if set to a larger number, calls to stdout will be buffered up to this value and then written to stdout.
    #[arg(short, long, default_value = "1024", verbatim_doc_comment)]
    buffer: u16,

    /// If captured packets should be printed to stdout in realtime, quiet mode can result in better performance as there won't be calls to print to console
    #[arg(short, long, default_value = "false", verbatim_doc_comment)]
    quiet: bool,

    /// Filters to apply to captured packets E.g src_port > 8000 or dst_port < 4000
    /// Multiple filters can be combined by commas (e.g src_ip > 8000, dst_ip < 4000)
    /// Each filter should be in the format <field> <operator> <value>
    /// Supported fields: src_ip, dst_ip, src_port, dst_port, transport
    /// Supported operators: >, <, >=, <=, ==, !=
    /// Example: --filter "src_ip == 192.168.1.1"
    /// Example: --filter "src_port >= 8000, dst_port < 4000"
    /// Note: A space must exist between the field, operator and value
    /// Note: No spaces between commas and next filter
    /// If no filter is provided, all packets are captured
    /// == and != operators are string comparisons and only valid for IP addresses and protocol
    /// >, <, >=, <= operators are numeric comparisons and only valid for ports
    #[arg(short, long, verbatim_doc_comment)]
    filter: Option<String>,

    /// time window to group packet statistics together before writing to output file
    /// Not supplying a window means that statistics will be aggregated in memory for the entire length of the program running which can lead to increased memory consumption
    #[arg(short, long, verbatim_doc_comment)]
    window: Option<u32>,

    /// Optional packet size limit for captured packets
    /// Setting to a lower value can result in better performance as less data is copied from kernel space to user space
    /// However, setting to a lower value means that some packets may be truncated and therefore dropped by the packet parser
    /// Default is 5000 bytes which should be sufficient for most use cases
    #[arg(long, default_value = "5000", verbatim_doc_comment)]
    max_packet_size: u16,

}

fn main() {
    let args = Args::parse();
    if args.devices {
        print_devices();
        std::process::exit(0);
    }
    let interface = args.interface.unwrap_or_else(|| {
        eprintln!("No interface provided!");
        std::process::exit(1);
    });
    let packet_info = Arc::new(Mutex::new(PacketInfo::new()));

    let sniffer_packet_info = Arc::clone(&packet_info);

    let reporter_signaller = Arc::new(ReporterSignaller::new());
    let user_input_reporter_signaller = Arc::clone(&reporter_signaller);

    let packet_filter = match args.filter {
        None => None,
        Some(filter_string) => {
            let filter = PacketFilter::new(&filter_string).unwrap_or_else(|e| {
                eprintln!("{}", format!("Error: {}", e));
                std::process::exit(1);
            });
            println!("The following Filter will be applied: {}", filter);
            Some(filter)
        }
    };

    let report_join_handle = match args.output {
        None => None,
        Some(output_folder) => {
            let reporter = Reporter::new(output_folder, args.window).unwrap_or_else(|e| {
                eprintln!("{}", format!("Error: {}", e));
                std::process::exit(1)
            });
            let handle =
                std::thread::spawn(move || reporter.start(packet_info, reporter_signaller));
            Some(handle)
        }
    };

    let status_mutex = Mutex::new(SniffStatus::RUNNING);
    let condvar = Condvar::new();

    let signaller = Arc::new(Signaller::new(status_mutex, condvar));

    let packet_parser_signal = Arc::clone(&signaller);

    let input_signal = Arc::clone(&signaller);

    enable_raw_mode().unwrap();
    let sniffer_handle = match Sniffer::new(interface, args.quiet, args.buffer, args.max_packet_size) {
        Ok(sniffer) => std::thread::spawn(move || {
            sniffer.start(packet_parser_signal, sniffer_packet_info, packet_filter)
        }),
        Err(e) => {
            eprintln!("Sniffer Error: {}\r\n", e);
            disable_raw_mode().unwrap();
            std::process::exit(1);
        }
    };

    read_user_input(input_signal);
    sniffer_handle.join();

    // stop reporter and make it run finalizers.
    // It's important this runs after the packet sniffer thread completes, so we don't miss out on packets.
    run_reporter_finalizers(report_join_handle, user_input_reporter_signaller);
    disable_raw_mode().unwrap();
    println!("Goodbye!");
}

fn run_reporter_finalizers(
    reporter_join_handle: Option<JoinHandle<()>>,
    reporter_signaller: Arc<ReporterSignaller>,
) {
    let mut reporter_status = reporter_signaller.mutex.lock().unwrap();
    *reporter_status = ReporterStatus::STOPPED;
    reporter_signaller.condvar.notify_one();
    drop(reporter_status);
    // block main thread until reporter completes so data is written to the underlying file
    reporter_join_handle.map(|join_handle| join_handle.join().unwrap());
}

fn read_user_input(signaller: Arc<Signaller>) {
    loop {
        match read().unwrap() {
            Event::Key(KeyEvent {
                code: KeyCode::Char(x),
                modifiers: KeyModifiers::NONE,
                ..
            }) => {
                match x {
                    'p' => {
                        let mut status = signaller.mutex.lock().unwrap();
                        *status = SniffStatus::PAUSED;
                        drop(status);
                    }
                    'r' => {
                        let mut status = signaller.mutex.lock().unwrap();
                        *status = SniffStatus::RUNNING;
                        drop(status);

                        // notify / wakeup the parsing and printing thread
                        signaller.condvar.notify_one();
                    }
                    _ => (),
                }
            }
            Event::Key(KeyEvent {
                code: KeyCode::Char('c'),
                modifiers: KeyModifiers::CONTROL,
                ..
            }) => {
                let mut status = signaller.mutex.lock().unwrap();
                *status = SniffStatus::STOPPED;
                drop(status);
                // if the printer thread is paused, wake it up, so that thread can exit
                signaller.condvar.notify_one();

                break;
            }
            _ => (),
        }
    }
    IP::UNCACHED("".to_string());
}
fn print_devices() {
    let mut DEVICE_COLUMN_WIDTH: usize = 20;
    const ADDRESS_COLUMN_WIDTH: usize = 50;

    let devices = pcap::Device::list().unwrap_or_else(|e| {
        eprintln!("Could not list devices: {}", e);
        std::process::exit(1);
    });

    let mut writer = BufWriter::new(std::io::stdout());

    let max_device_name_length = devices
        .iter()
        .map(|d| d.name.len() + 2)
        .max()
        .unwrap_or(DEVICE_COLUMN_WIDTH);

    DEVICE_COLUMN_WIDTH = DEVICE_COLUMN_WIDTH.max(max_device_name_length); // add some padding

    let hyphen_line = format!("{}{}{}", "+", "-".repeat(DEVICE_COLUMN_WIDTH + 54), "+");
    writer
        .write_all(format!("{}\n", hyphen_line).as_bytes())
        .unwrap();
    writer
        .write_all(
            format!(
                "| {0: <DEVICE_COLUMN_WIDTH$} | {1: <ADDRESS_COLUMN_WIDTH$}|\n",
                "Device Name",
                "Addresses",
                DEVICE_COLUMN_WIDTH = DEVICE_COLUMN_WIDTH,
                ADDRESS_COLUMN_WIDTH = ADDRESS_COLUMN_WIDTH
            )
            .as_bytes(),
        )
        .unwrap();
    writer
        .write_all(format!("{}\n", hyphen_line).as_bytes())
        .unwrap();
    for device in devices.iter() {
        if device.addresses.is_empty() {
            writer
                .write_all(
                    format!(
                        "| {0: <DEVICE_COLUMN_WIDTH$} | {1: <ADDRESS_COLUMN_WIDTH$}|\n",
                        &device.name,
                        "",
                        DEVICE_COLUMN_WIDTH = DEVICE_COLUMN_WIDTH,
                        ADDRESS_COLUMN_WIDTH = ADDRESS_COLUMN_WIDTH
                    )
                    .as_bytes(),
                )
                .unwrap();
            writer
                .write_all(format!("{}\n", hyphen_line).as_bytes())
                .unwrap();
        } else {
            let mut name_written = false;
            for address in device.addresses.iter() {
                let name = if name_written { "" } else { &device.name };
                writer
                    .write_all(
                        format!(
                            "| {0: <DEVICE_COLUMN_WIDTH$} | {1: <ADDRESS_COLUMN_WIDTH$}|\n",
                            name,
                            address.addr.to_string(),
                            DEVICE_COLUMN_WIDTH = DEVICE_COLUMN_WIDTH,
                            ADDRESS_COLUMN_WIDTH = ADDRESS_COLUMN_WIDTH
                        )
                        .as_bytes(),
                    )
                    .unwrap();
                name_written = true
            }
            writer
                .write_all(format!("{}\n", hyphen_line).as_bytes())
                .unwrap();
        }
    }
}
