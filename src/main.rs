mod models;
mod reporter;
mod sniffed_packet;
mod sniffer;
mod utils;

use crate::models::{PacketInfo, ReporterSignaller, ReporterStatus, Signaller, SniffStatus};
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

/// Packet Sniffing Program
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Print devices on system and exits
    #[arg(short, long)]
    devices: bool,

    /// interface to sniff, if not supplied, will default to default interface on machine
    #[arg(short, long, default_value_t = String::new())]
    interface: String,

    /// output folder where report will be written to
    #[arg(short, long)]
    output: Option<PathBuf>,
}

fn main() {
    let args = Args::parse();
    if args.devices {
        print_devices();
        std::process::exit(0);
    }

    let packetInfo = Arc::new(PacketInfo::new());

    let reporter_packet_info = Arc::clone(&packetInfo);

    let sniffer_packet_info = Arc::clone(&packetInfo);

    let reporter_signaller = Arc::new(ReporterSignaller::new());
    let user_input_reporter_signaller = Arc::clone(&reporter_signaller);

    let report_join_handle = match args.output {
        None => None,
        Some(output_folder) => {
            let reporter = Reporter::new(output_folder).expect("Can't create reporter");
            let handle = std::thread::spawn(move || reporter.start(packetInfo, reporter_signaller));
            Some(handle)
        }
    };

    let status_mutex = Mutex::new(SniffStatus::RUNNING);
    let condvar = Condvar::new();

    let signaller = Arc::new(Signaller::new(status_mutex, condvar));

    let packet_parser_signal = Arc::clone(&signaller);

    let input_signal = Arc::clone(&signaller);

    enable_raw_mode().unwrap();
    let sniffer_handle = match Sniffer::new(args.interface) {
        Ok(sniffer) => {
            std::thread::spawn(move || sniffer.start(packet_parser_signal, sniffer_packet_info))
        }
        Err(e) => {
            eprintln!("Sniffer Error:\r\n{}", e);
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
}
fn print_devices() {
    const DEVICE_COLUMN_WIDTH: usize = 20;
    const ADDRESS_COLUMN_WIDTH: usize = 50;

    let devices = pcap::Device::list().expect("Could not list devices");

    let mut writer = BufWriter::new(std::io::stdout());
    let hyphen_line = format!("{}{}{}", "+", "-".repeat(74_usize), "+");

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
