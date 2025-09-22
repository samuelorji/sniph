use crate::models::{PacketInfo, PacketLink, PacketLinkStats, ReporterSignaller, ReporterStatus};
use crate::utils::format_number_to_bytes;
use chrono::{Local, TimeDelta};
use indexmap::IndexMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::mem;
use std::ops::Add;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Reporter is responsible for periodically writing packet statistics to a CSV file.
/// It runs in its own thread and checks for a stop signal to terminate gracefully.
/// It uses a mutex to safely access shared packet information with the sniffer thread.
/// It creates a new CSV file in the specified output folder with a timestamped filename.
pub struct Reporter {
    output_folder: PathBuf,
    time_interval_secs: u32,
    file: File,
}

impl Reporter {
    pub fn new(output_folder: PathBuf) -> Result<Reporter, String> {
        if let Ok(false) = std::fs::exists(&output_folder) {
            // output folder doesn't exist, create it
            std::fs::create_dir(&output_folder)
                .map_err(|e| format!("Failed to create output folder: {}", e))?
        }

        let file_name =
            output_folder.join(format!("{}.csv", Local::now().format("%Y_%m_%d_%H_%M_%S")));
        let file = File::options()
            .append(true)
            .create(true)
            .open(file_name)
            .expect("Failed to open output file");

        Ok(Reporter {
            output_folder,
            time_interval_secs: 5,
            file,
        })
    }

    pub fn start(
        &self,
        mut packet_info: Arc<Mutex<PacketInfo>>,
        signaller: Arc<ReporterSignaller>,
    ) {
        let mut buf_writer = BufWriter::new(&self.file);
        let mut header_written = false;
        let mut next_reporting =
            Local::now().add(TimeDelta::seconds(self.time_interval_secs as i64));
        loop {
            let mut status = signaller.mutex.lock().unwrap();
            if *status == ReporterStatus::STOPPED {
                drop(status);
                self.write_stats(&mut packet_info, &mut buf_writer, &mut header_written);
                break;
            } else {
                while *status != ReporterStatus::STOPPED && Local::now() < next_reporting {
                    status = signaller
                        .condvar
                        .wait_timeout(
                            status,
                            Duration::from_secs((self.time_interval_secs) as u64),
                        )
                        .unwrap()
                        .0;
                }
                drop(status);
                self.write_stats(&mut packet_info, &mut buf_writer, &mut header_written);
                next_reporting =
                    next_reporting.add(TimeDelta::seconds(self.time_interval_secs as i64));
            }
        }
    }

    fn write_stats(
        &self,
        packet_info: &mut Arc<Mutex<PacketInfo>>,
        buf_writer: &mut BufWriter<&File>,
        header_written: &mut bool,
    ) {
        let mut packet_stats = &mut packet_info.lock().unwrap().packet_mapping;
        if packet_stats.is_empty() {
            return;
        }
        // replace mutex with new index map to be used by the sniffer thread
        let local_stats = mem::replace(&mut *packet_stats, IndexMap::new());
        // drop mutex so it can be used by sniffer thread
        drop(packet_stats);
        Self::write_csv_output(buf_writer, local_stats, header_written);
    }

    fn write_csv_output(
        writer: &mut BufWriter<&File>,
        stats: IndexMap<PacketLink, PacketLinkStats>,
        header_written: &mut bool,
    ) {
        if !*header_written {
            writer.write_all(
                format!(
                    "{},{},{},{},{},{},{},{},{},{},{}",
                    "src_ip",
                    "dest_ip",
                    "src_port",
                    "dest_port",
                    "ip_version",
                    "transport_protocol",
                    "traffic_direction",
                    "num_packets",
                    "bytes_transferred",
                    "start_time",
                    "end_time"
                )
                .as_bytes(),
            );
        }
        *header_written = true;
        for (link, stats) in stats {
            writer.write_all(
                format!(
                    "\n{},{},{},{},{},{},{},{},{},{},{}",
                    link.src_ip,
                    link.dest_ip,
                    link.src_port,
                    link.dest_port,
                    stats.ip_version,
                    link.transport_protocol,
                    stats.traffic_direction,
                    stats.num_packets,
                    stats.num_bytes,
                    stats.start_time.format("%Y-%m-%d %H:%M:%S"),
                    stats.end_time.format("%Y-%m-%d %H:%M:%S")
                )
                .as_bytes(),
            );
        }

        writer.flush().unwrap();
    }
}
