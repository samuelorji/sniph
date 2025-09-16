mod models;
mod sniffed_packet;
mod sniffer;

use crate::models::{Signaller, SniffStatus};
use crate::sniffer::Sniffer;
use clap::Parser;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers, read};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use pcap::{Capture, Device, Error, Packet};
use std::fmt::format;
use std::io::{BufWriter, Write};
use std::sync::{Arc, Condvar, Mutex};

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

    let status_mutex = Mutex::new(SniffStatus::RUNNING);
    let condvar = Condvar::new();

    let signaller = Arc::new(Signaller::new(status_mutex, condvar));

    let packet_parser_signal = Arc::clone(&signaller);

    let input_signal = Arc::clone(&signaller);

    enable_raw_mode().unwrap();
    let sniffer_handle = match Sniffer::new(args.interface) {
        Ok(sniffer) => std::thread::spawn(move || sniffer.start(packet_parser_signal)),
        Err(e) => {
            eprintln!("Sniffer Error:\r\n{}", e);
            disable_raw_mode().unwrap();
            std::process::exit(1);
        }
    };

    read_user_input(input_signal);
    sniffer_handle.join();
    disable_raw_mode().unwrap();
    println!("Goodbye!");
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
