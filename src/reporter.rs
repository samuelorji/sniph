use crate::models::{PacketInfo, PacketLink, PacketLinkStats, ReporterSignaller, ReporterStatus};
use crate::utils::format_number_to_units;
use chrono::{DateTime, Local, TimeDelta};
use indexmap::IndexMap;
use plotters::backend::SVGBackend;
use plotters::chart::{ChartBuilder, LabelAreaPosition};
use plotters::drawing::IntoDrawingArea;
use plotters::prelude::full_palette::GREY_300;
use plotters::prelude::{AreaSeries, BLACK, BLUE, Color, IntoFont};
use plotters::style::RED;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::mem;
use std::ops::Sub;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Reporter is responsible for periodically writing packet statistics to a CSV file.
/// It runs in its own thread and checks for a stop signal to terminate gracefully.
/// It uses a mutex to safely access shared packet information with the sniffer thread.
pub struct Reporter {
    output_folder: PathBuf,
    // interval to write to csv file after wakeup
    csv_write_interval: Option<u32>,
    // how often to wake up from thread sleep
    wakeup_interval_secs: u8,
    // csv output file
    csv_file: File,
    // svg file to write data throughput graphs
    data_throughput_file: String,
    // svg file to write packet throughput graphs
    packet_throughput_file: String,
}

impl Reporter {
    pub fn new(
        output_folder: PathBuf,
        time_interval_secs: Option<u32>,
    ) -> Result<Reporter, String> {
        let formatted_date = Local::now().format("%Y_%m_%d_%H_%M_%S");
        let report_folder = output_folder.join(format!("report_{}", &formatted_date));

        match std::fs::exists(&report_folder) {
            Ok(exists) => {
                if !exists {
                    std::fs::create_dir_all(&report_folder)
                        .map_err(|e| format!("Failed to create output folder: {}", e))?;
                } else {
                    println!("Report folder already exists, will overwrite reports within\r");
                }
            }
            Err(_) => {
                return Err(format!(
                    "Failed to report folder: {}",
                    &report_folder.to_str().unwrap()
                ));
            }
        }

        let csv_write_interval = match time_interval_secs {
            None => Ok(None),
            Some(supplied_interval) => {
                if supplied_interval % 2 != 0 {
                    Err("time window must be an even number".to_string())
                } else {
                    Ok(Some(supplied_interval / 2))
                }
            }
        }?;

        let csv_file_name = report_folder.join("report.csv");
        let data_throughput_file_name = report_folder.join("data_throughput.svg");
        let packet_throughput_file_name = report_folder.join("packet_throughput.svg");
        let file = File::options()
            .append(true)
            .create(true)
            .open(csv_file_name)
            .map_err(|e| format!("Failed to open output file, reason: {}", e))?;

        Ok(Reporter {
            output_folder,
            csv_write_interval,
            wakeup_interval_secs: 2,
            csv_file: file,
            data_throughput_file: data_throughput_file_name
                .as_path()
                .to_str()
                .unwrap()
                .to_string(),
            packet_throughput_file: packet_throughput_file_name
                .as_path()
                .to_str()
                .unwrap()
                .to_string(),
        })
    }

    pub fn start(
        &self,
        mut packet_info: Arc<Mutex<PacketInfo>>,
        signaller: Arc<ReporterSignaller>,
    ) {
        let mut buf_writer = BufWriter::new(&self.csv_file);
        let mut header_written = false;
        let mut csv_interval: u32 = 0;
        let mut data_throughput_graph_error = String::new();
        let start_time = Local::now();
        let mut outgoing_data_throughput = OutgoingDataThroughputParams::new(&start_time);
        let mut incoming_data_throughput = IncomingDataThroughputParams::new(&start_time);
        let mut outgoing_packet_throughput = OutgoingPacketThroughputParams::new(&start_time);
        let mut incoming_packet_throughput = IncomingPacketThroughputParams::new(&start_time);
        let mut sleep_over = false;
        loop {
            sleep_over = false;
            let mut status = signaller.mutex.lock().unwrap();
            csv_interval += 1;
            if *status == ReporterStatus::STOPPED {
                drop(status);

                self.write_report(
                    &mut packet_info,
                    &mut header_written,
                    &mut csv_interval,
                    &mut buf_writer,
                    true,
                    &mut data_throughput_graph_error,
                    &mut outgoing_data_throughput,
                    &mut incoming_data_throughput,
                    &mut outgoing_packet_throughput,
                    &mut incoming_packet_throughput,
                );

                if !data_throughput_graph_error.is_empty() {
                    eprintln!("{}\r", data_throughput_graph_error);
                }
                break;
            } else {
                // we may run into spurious wakeup, and that's fine, we can tolerate it
                while *status != ReporterStatus::STOPPED && !sleep_over {
                    status = signaller
                        .condvar
                        .wait_timeout(
                            status,
                            Duration::from_millis((self.wakeup_interval_secs as u64 * 1000) - 9), // csv and graphing typically takes 10ms
                        )
                        .unwrap()
                        .0;

                    sleep_over = !sleep_over;
                }
                drop(status);

                self.write_report(
                    &mut packet_info,
                    &mut header_written,
                    &mut csv_interval,
                    &mut buf_writer,
                    false,
                    &mut data_throughput_graph_error,
                    &mut outgoing_data_throughput,
                    &mut incoming_data_throughput,
                    &mut outgoing_packet_throughput,
                    &mut incoming_packet_throughput,
                );
            }
        }
    }

    fn write_report(
        &self,
        mut packet_info: &mut Arc<Mutex<PacketInfo>>,
        mut header_written: &mut bool,
        csv_interval_counter: &mut u32,
        mut buf_writer: &mut BufWriter<&File>,
        flush_csv: bool,
        data_throughput_graph_error: &mut String,
        outgoing_data_throughput_params: &mut OutgoingDataThroughputParams,
        incoming_data_throughput_params: &mut IncomingDataThroughputParams,
        outgoing_packet_throughput_params: &mut OutgoingPacketThroughputParams,
        incoming_packet_throughput_params: &mut IncomingPacketThroughputParams,
    ) {
        let mut packet_info_mutex = packet_info.lock().unwrap();
        outgoing_data_throughput_params.current_max_data_point =
            packet_info_mutex.stats.transferred_bytes;
        incoming_data_throughput_params.current_max_data_point =
            packet_info_mutex.stats.received_bytes;
        outgoing_packet_throughput_params.current_max_data_point =
            packet_info_mutex.stats.packets_sent;
        incoming_packet_throughput_params.current_max_data_point =
            packet_info_mutex.stats.packets_received;

        let current_write_time_window = packet_info_mutex.current_write_time_window.clone();
        let mut packet_mapping = &mut packet_info_mutex.packet_mapping;

        let mut local_stats = IndexMap::new();

        let is_write_interval = if let Some(interval) = self.csv_write_interval {
            interval == *csv_interval_counter
        } else {
            false
        };

        if is_write_interval {
            *csv_interval_counter = 0
        }

        if (flush_csv || is_write_interval) && !packet_mapping.is_empty() {
            // get the map from the mutex and replace with an empty one to be used by the sniffer
            local_stats = mem::replace(&mut *packet_mapping, local_stats);
        }
        drop(packet_info_mutex);

        if !local_stats.is_empty() {
            Self::write_csv_output(
                &mut buf_writer,
                local_stats,
                current_write_time_window,
                &mut header_written,
            );
        }

        // TODO
        // do something better than writing the very first error to stderr
        self.write_data_throughput_report(
            outgoing_data_throughput_params,
            incoming_data_throughput_params,
        )
        .map_err(|e| *data_throughput_graph_error = e);

        self.write_packet_throughput_report(
            outgoing_packet_throughput_params,
            incoming_packet_throughput_params,
        )
        .map_err(|e| *data_throughput_graph_error = e);
    }

    fn write_data_throughput_report(
        &self,
        outgoing_data_throughput_params: &mut OutgoingDataThroughputParams,
        incoming_data_throughput_params: &mut IncomingDataThroughputParams,
    ) -> Result<(), String> {
        let now = Local::now();

        let out = outgoing_data_throughput_params;
        out.time_in_seconds_since_start = now.sub(out.start_time).num_seconds();
        // transfer bytes update
        let transfer_bytes_interval: u32 =
            (out.current_max_data_point - out.previous_data_point) as u32;
        if transfer_bytes_interval >= out.largest_throughput_delta {
            out.largest_throughput_delta = transfer_bytes_interval;
        }
        out.throughput_record.push((
            out.time_in_seconds_since_start as u32,
            transfer_bytes_interval,
        ));
        out.previous_data_point = out.current_max_data_point;

        let screen_resolution_width = 1280;
        let screen_resolution_height = 720;

        let graph_max_width: u32 = 1250;
        let graph_max_height: u32 = 700;
        let canvas = SVGBackend::new(
            &self.data_throughput_file,
            (screen_resolution_width, screen_resolution_height),
        )
        .into_drawing_area();
        canvas
            .fill(&GREY_300)
            .map_err(|e| format!("Error drawing graph: {}", e))?;
        let (graph_window, _) = canvas.split_horizontally(graph_max_width);
        let (mut tx_bytes_window, mut rx_bytes_window) =
            graph_window.split_vertically(graph_max_height / 2);
        tx_bytes_window = tx_bytes_window.margin(5, 0, 5, 5);
        rx_bytes_window = rx_bytes_window.margin(5, 0, 5, 5);
        let (_, footer) = canvas.split_vertically(graph_max_height);
        footer
            .titled(
                &format!(
                    "Charts are updated every {} seconds. Please reload to see changes",
                    out.chart_update_time_interval_secs
                ),
                ("sans-serif", 18).into_font().color(&BLACK),
            )
            .map_err(|e| format!("Error drawing graph: {}", e))?;

        let mut transfer_bytes_chart = ChartBuilder::on(&tx_bytes_window)
            // set title of chart
            .caption(
                "Outgoing Traffic Throughput: Bytes/second",
                ("sans-serif", 20),
            )
            // set the size of the label
            .set_label_area_size(LabelAreaPosition::Left, 65)
            .set_label_area_size(LabelAreaPosition::Bottom, 50)
            // build a 2d cartesian, with the x axis being range of values (in our case will be time), y axis will be range of values for bytes transferred
            .build_cartesian_2d(
                0..out.time_in_seconds_since_start as u32,
                0..(out.largest_throughput_delta as f64 * 1.2) as u32,
            )
            .map_err(|e| format!("Error drawing graph: {}", e))?;

        transfer_bytes_chart
            .configure_mesh()
            // define the labels
            .y_desc("bytes/s")
            .label_style(("sans-serif", 10))
            .axis_desc_style(("sans-serif", 12))
            .x_label_formatter(&|seconds| {
                (*out.start_time + TimeDelta::seconds(*seconds as i64))
                    .format("%H:%M:%S")
                    .to_string()
            })
            .y_label_formatter(&|bits| format!("{}B", format_number_to_units(*bits as u128)))
            .draw()
            .map_err(|e| format!("Error drawing graph: {}", e))?;
        // we're copying the values in the vec, in our case, it should be the same as clone because the underlying
        // vec type is a copy,
        let rec = out.throughput_record.iter().copied();

        let _ = transfer_bytes_chart
            .draw_series(AreaSeries::new(rec, 0, RED.filled()).border_style(&RED))
            .map_err(|e| format!("Error drawing graph: {}", e))?;

        drop(out); // make sure the outgoing variable is not mistakenly used anymore

        /*
        +---------------------+
        | INCOMING DATA GRAPH |
        +---------------------+
        */
        incoming_data_throughput_params.time_in_seconds_since_start = now
            .sub(incoming_data_throughput_params.start_time)
            .num_seconds();

        let incoming = incoming_data_throughput_params;
        // received bytes update
        let transfer_bytes_interval =
            (incoming.current_max_data_point - incoming.previous_data_point) as u32;
        if transfer_bytes_interval >= incoming.largest_throughput_delta {
            incoming.largest_throughput_delta = transfer_bytes_interval;
        }
        incoming.throughput_record.push((
            incoming.time_in_seconds_since_start as u32,
            transfer_bytes_interval,
        ));
        incoming.previous_data_point = incoming.current_max_data_point;

        let mut rx_bytes_chart = ChartBuilder::on(&rx_bytes_window)
            // set title of chart
            .caption(
                "Incoming Traffic Throughput: Bytes/second",
                ("sans-serif", 20),
            )
            // set the size of the label
            .set_label_area_size(LabelAreaPosition::Left, 65)
            .set_label_area_size(LabelAreaPosition::Bottom, 50)
            // build a 2d cartesian, with the x axis being range of values (in our case will be time), y axis will be range of values for bytes transferred
            .build_cartesian_2d(
                0..incoming.time_in_seconds_since_start as u32,
                0..(incoming.largest_throughput_delta as f64 * 1.2) as u32,
            )
            .map_err(|e| format!("Error drawing graph: {}", e))?;

        rx_bytes_chart
            .configure_mesh()
            // define the labels
            .y_desc("bytes/s")
            .label_style(("sans-serif", 10))
            .axis_desc_style(("sans-serif", 12))
            .x_label_formatter(&|seconds| {
                (*incoming.start_time + TimeDelta::seconds(*seconds as i64))
                    .format("%H:%M:%S")
                    .to_string()
            })
            .y_label_formatter(&|bits| format!("{}B", format_number_to_units(*bits as u128)))
            .draw()
            .map_err(|e| format!("Error drawing graph: {}", e))?;
        // we're copying the values in the vec, in our case, it should be the same as clone because the underlying
        // vec type is a copy,
        let rec = incoming.throughput_record.iter().copied();

        rx_bytes_chart
            .draw_series(AreaSeries::new(rec, 0, BLUE.filled()).border_style(&BLUE))
            .map_err(|e| format!("Error drawing graph: {}", e))?;

        Ok(())
    }

    // Duplicate of write data throughput ....
    // No strength to make this DRY :)
    fn write_packet_throughput_report(
        &self,
        outgoing_packet_throughput_params: &mut OutgoingPacketThroughputParams,
        incoming_packet_throughput_params: &mut IncomingPacketThroughputParams,
    ) -> Result<(), String> {
        let now = Local::now();

        let out = outgoing_packet_throughput_params;
        out.time_in_seconds_since_start = now.sub(out.start_time).num_seconds();

        // transfer bytes update
        let transfer_bytes_interval: u32 =
            (out.current_max_data_point - out.previous_data_point) as u32;
        if transfer_bytes_interval >= out.largest_throughput_delta {
            out.largest_throughput_delta = transfer_bytes_interval;
        }
        out.throughput_record.push((
            out.time_in_seconds_since_start as u32,
            transfer_bytes_interval,
        ));
        out.previous_data_point = out.current_max_data_point;

        let screen_resolution_width = 1280;
        let screen_resolution_height = 720;

        let graph_max_width: u32 = 1250;
        let graph_max_height: u32 = 700;
        let canvas = SVGBackend::new(
            &self.packet_throughput_file,
            (screen_resolution_width, screen_resolution_height),
        )
        .into_drawing_area();
        canvas
            .fill(&GREY_300)
            .map_err(|e| format!("Error drawing graph: {}", e))?;
        let (graph_window, _) = canvas.split_horizontally(graph_max_width);
        let (mut tx_window, mut rx_window) = graph_window.split_vertically(graph_max_height / 2);
        tx_window = tx_window.margin(5, 0, 5, 5);
        rx_window = rx_window.margin(5, 0, 5, 5);
        let (_, footer) = canvas.split_vertically(graph_max_height);
        footer
            .titled(
                &format!(
                    "Charts are updated every {} seconds. Please reload to see changes",
                    out.chart_update_time_interval_secs
                ),
                ("sans-serif", 18).into_font().color(&BLACK),
            )
            .map_err(|e| format!("Error drawing graph: {}", e))?;

        let mut transfer_packets_chart = ChartBuilder::on(&tx_window)
            // set title of chart
            .caption(
                "Outgoing Traffic Throughput: Packets/second",
                ("sans-serif", 20),
            )
            // set the size of the label
            .set_label_area_size(LabelAreaPosition::Left, 65)
            .set_label_area_size(LabelAreaPosition::Bottom, 50)
            // build a 2d cartesian, with the x axis being range of values (in our case will be time), y axis will be range of values for bytes transferred
            .build_cartesian_2d(
                0..out.time_in_seconds_since_start as u32,
                0..(out.largest_throughput_delta as f64 * 1.2) as u32,
            )
            .map_err(|e| format!("Error drawing graph: {}", e))?;

        transfer_packets_chart
            .configure_mesh()
            // define the labels
            .y_desc("bytes/s")
            .label_style(("sans-serif", 10))
            .axis_desc_style(("sans-serif", 12))
            .x_label_formatter(&|seconds| {
                (*out.start_time + TimeDelta::seconds(*seconds as i64))
                    .format("%H:%M:%S")
                    .to_string()
            })
            .y_label_formatter(&|bits| format!("{}", format_number_to_units(*bits as u128)))
            .draw()
            .map_err(|e| format!("Error drawing graph: {}", e))?;
        // we're copying the values in the vec, in our case, it should be the same as clone because the underlying
        // vec type is a copy,
        let rec = out.throughput_record.iter().copied();

        let _ = transfer_packets_chart
            .draw_series(AreaSeries::new(rec, 0, RED.filled()).border_style(&RED))
            .map_err(|e| format!("Error drawing graph: {}", e))?;

        drop(out); // make sure the outgoing variable is not mistakenly used anymore

        /*
        +---------------------+
        | INCOMING DATA GRAPH |
        +---------------------+
        */
        incoming_packet_throughput_params.time_in_seconds_since_start = now
            .sub(incoming_packet_throughput_params.start_time)
            .num_seconds();

        let incoming = incoming_packet_throughput_params;
        // received bytes update
        let transfer_interval =
            (incoming.current_max_data_point - incoming.previous_data_point) as u32;
        if transfer_interval >= incoming.largest_throughput_delta {
            incoming.largest_throughput_delta = transfer_interval;
        }
        incoming.throughput_record.push((
            incoming.time_in_seconds_since_start as u32,
            transfer_interval,
        ));
        incoming.previous_data_point = incoming.current_max_data_point;

        let mut rx_bytes_chart = ChartBuilder::on(&rx_window)
            // set title of chart
            .caption(
                "Incoming Traffic Throughput: Packets/second",
                ("sans-serif", 20),
            )
            // set the size of the label
            .set_label_area_size(LabelAreaPosition::Left, 65)
            .set_label_area_size(LabelAreaPosition::Bottom, 50)
            // build a 2d cartesian, with the x axis being range of values (in our case will be time), y axis will be range of values for bytes transferred
            .build_cartesian_2d(
                0..incoming.time_in_seconds_since_start as u32,
                0..(incoming.largest_throughput_delta as f64 * 1.2) as u32,
            )
            .map_err(|e| format!("Error drawing graph: {}", e))?;

        rx_bytes_chart
            .configure_mesh()
            // define the labels
            .y_desc("bytes/s")
            .label_style(("sans-serif", 10))
            .axis_desc_style(("sans-serif", 12))
            .x_label_formatter(&|seconds| {
                (*incoming.start_time + TimeDelta::seconds(*seconds as i64))
                    .format("%H:%M:%S")
                    .to_string()
            })
            .y_label_formatter(&|bits| format!("{}", format_number_to_units(*bits as u128)))
            .draw()
            .map_err(|e| format!("Error drawing graph: {}", e))?;
        // we're copying the values in the vec, in our case, it should be the same as clone because the underlying
        // vec type is a copy,
        let rec = incoming.throughput_record.iter().copied();

        rx_bytes_chart
            .draw_series(AreaSeries::new(rec, 0, BLUE.filled()).border_style(&BLUE))
            .map_err(|e| format!("Error drawing graph: {}", e))?;

        Ok(())
    }

    fn write_csv_output(
        writer: &mut BufWriter<&File>,
        stats: IndexMap<PacketLink, PacketLinkStats>,
        current_time_window: Arc<DateTime<Local>>,
        header_written: &mut bool,
    ) {
        if !*header_written {
            writer.write_all(
                format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{}",
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
                    "end_time",
                    "time_window_start"
                )
                .as_bytes(),
            );
        }
        *header_written = true;
        for (link, stats) in stats {
            writer.write_all(
                format!(
                    "\n{},{},{},{},{},{},{},{},{},{},{},{}",
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
                    stats.end_time.format("%Y-%m-%d %H:%M:%S"),
                    current_time_window.format("%Y-%m-%d %H:%M:%S")
                )
                .as_bytes(),
            );
        }

        writer.flush().unwrap();
    }
}

struct OutgoingDataThroughputParams<'a> {
    start_time: &'a DateTime<Local>,
    time_in_seconds_since_start: i64,
    current_max_data_point: u128,
    previous_data_point: u128,
    largest_throughput_delta: u32,
    throughput_record: Vec<(u32, u32)>, // corresponds to a point in time and the throughput delta
    chart_update_time_interval_secs: u8,
}

impl<'a> OutgoingDataThroughputParams<'a> {
    fn new(start_time: &'a DateTime<Local>) -> Self {
        let mut record: Vec<(u32, u32)> = Vec::with_capacity(1000);
        record.push((0, 0));
        OutgoingDataThroughputParams {
            start_time,
            time_in_seconds_since_start: 0,
            current_max_data_point: 0,
            previous_data_point: 0,
            largest_throughput_delta: 0,
            throughput_record: record,
            chart_update_time_interval_secs: 2,
        }
    }
}

struct IncomingDataThroughputParams<'a> {
    start_time: &'a DateTime<Local>,
    time_in_seconds_since_start: i64,
    current_max_data_point: u128,
    previous_data_point: u128,
    largest_throughput_delta: u32,
    throughput_record: Vec<(u32, u32)>,
    chart_update_time_interval_secs: u8,
}

impl<'a> IncomingDataThroughputParams<'a> {
    fn new(start_time: &'a DateTime<Local>) -> Self {
        let mut record: Vec<(u32, u32)> = Vec::with_capacity(1000);
        record.push((0, 0));
        IncomingDataThroughputParams {
            start_time,
            time_in_seconds_since_start: 0,
            current_max_data_point: 0,
            previous_data_point: 0,
            largest_throughput_delta: 0,
            throughput_record: record,
            chart_update_time_interval_secs: 2,
        }
    }
}

struct IncomingPacketThroughputParams<'a> {
    start_time: &'a DateTime<Local>,
    time_in_seconds_since_start: i64,
    current_max_data_point: u128,
    previous_data_point: u128,
    largest_throughput_delta: u32,
    throughput_record: Vec<(u32, u32)>,
    chart_update_time_interval_secs: u8,
}

impl<'a> IncomingPacketThroughputParams<'a> {
    fn new(start_time: &'a DateTime<Local>) -> Self {
        let mut record: Vec<(u32, u32)> = Vec::with_capacity(1000);
        record.push((0, 0));
        IncomingPacketThroughputParams {
            start_time,
            time_in_seconds_since_start: 0,
            current_max_data_point: 0,
            previous_data_point: 0,
            largest_throughput_delta: 0,
            throughput_record: record,
            chart_update_time_interval_secs: 2,
        }
    }
}

struct OutgoingPacketThroughputParams<'a> {
    start_time: &'a DateTime<Local>,
    time_in_seconds_since_start: i64,
    current_max_data_point: u128,
    previous_data_point: u128,
    largest_throughput_delta: u32,
    throughput_record: Vec<(u32, u32)>,
    chart_update_time_interval_secs: u8,
}

impl<'a> OutgoingPacketThroughputParams<'a> {
    fn new(start_time: &'a DateTime<Local>) -> Self {
        let mut record: Vec<(u32, u32)> = Vec::with_capacity(1000);
        record.push((0, 0));
        OutgoingPacketThroughputParams {
            start_time,
            time_in_seconds_since_start: 0,
            current_max_data_point: 0,
            previous_data_point: 0,
            largest_throughput_delta: 0,
            throughput_record: record,
            chart_update_time_interval_secs: 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{IPVersion, TrafficDirection, TransportProtocol, IP, ApplicationProtocol};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    fn create_temp_reporter(interval: Option<u32>) -> (Reporter, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let reporter = Reporter::new(temp_dir.path().to_path_buf(), interval).unwrap();
        (reporter, temp_dir)
    }

    fn create_sample_packet_info() -> Arc<Mutex<PacketInfo>> {
        let mut packet_info = PacketInfo {
            packet_mapping: IndexMap::new(),
            stats: crate::models::PacketStatistics {
                packets_sent: 100,
                packets_received: 150,
                transferred_bytes: 5000,
                received_bytes: 7500,
                captured_packets: 250,
                skipped_packets: 0,
                filtered_packets: 0,
            },
            current_write_time_window: Arc::new(Local::now()),
        };

        // Add sample packet link data
        let link = PacketLink {
            src_ip: IP::CACHED(Arc::from("192.168.1.1")),
            dest_ip: IP::CACHED(Arc::from("192.168.1.2")),
            src_port: 8080,
            dest_port: 443,
            transport_protocol: TransportProtocol::TCP,
        };

        let stats = PacketLinkStats {
            ip_version: IPVersion::IPV4,
            traffic_direction: TrafficDirection::OUTGOING,
            num_packets: 50,
            num_bytes: 2500,
            start_time: Local::now() - TimeDelta::seconds(10),
            end_time: Local::now(),
            application_protocol: ApplicationProtocol::Other,
        };

        packet_info.packet_mapping.insert(link, stats);
        Arc::new(Mutex::new(packet_info))
    }

    #[test]
    fn test_new_reporter_valid_interval() {
        let temp_dir = TempDir::new().unwrap();
        let result = Reporter::new(temp_dir.path().to_path_buf(), Some(4));
        assert!(result.is_ok());

        let reporter = result.unwrap();
        assert_eq!(reporter.csv_write_interval, Some(2));
        assert_eq!(reporter.wakeup_interval_secs, 2);
    }

    #[test]
    fn test_new_reporter_invalid_odd_interval() {
        let temp_dir = TempDir::new().unwrap();
        let result = Reporter::new(temp_dir.path().to_path_buf(), Some(3));
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "time window must be an even number");
    }

    #[test]
    fn test_new_reporter_no_interval() {
        let temp_dir = TempDir::new().unwrap();
        let result = Reporter::new(temp_dir.path().to_path_buf(), None);
        assert!(result.is_ok());

        let reporter = result.unwrap();
        assert_eq!(reporter.csv_write_interval, None);
    }

    #[test]
    fn test_new_reporter_creates_directory_structure() {
        let temp_dir = TempDir::new().unwrap();
        let _reporter = Reporter::new(temp_dir.path().to_path_buf(), Some(4)).unwrap();

        // Check that report directory was created
        let entries: Vec<_> = std::fs::read_dir(temp_dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);

        let report_dir = entries[0].as_ref().unwrap().path();
        assert!(report_dir.is_dir());
        assert!(report_dir.file_name().unwrap().to_str().unwrap().starts_with("report_"));

        // Check that CSV file exists
        let csv_file = report_dir.join("report.csv");
        assert!(csv_file.exists());
    }

    #[test]
    fn test_write_csv_output() {
        let temp_dir = TempDir::new().unwrap();
        let csv_file = temp_dir.path().join("test.csv");
        let file = File::create(&csv_file).unwrap();
        let mut writer = BufWriter::new(&file);
        let mut header_written = false;

        let mut stats = IndexMap::new();
         // Add sample packet link data
        let link = PacketLink {
            src_ip: IP::CACHED(Arc::from("192.168.1.1")),
            dest_ip: IP::CACHED(Arc::from("192.168.1.2")),
            src_port: 8080,
            dest_port: 443,
            transport_protocol: TransportProtocol::TCP,
        };

        let packet_stats = PacketLinkStats {
            ip_version: IPVersion::IPV4,
            traffic_direction: TrafficDirection::OUTGOING,
            num_packets: 50,
            num_bytes: 2500,
            start_time: Local::now() - TimeDelta::seconds(10),
            end_time: Local::now(),
            application_protocol: ApplicationProtocol::Other,
        };

        stats.insert(link, packet_stats);
        let time_window = Arc::new(Local::now());

        Reporter::write_csv_output(&mut writer, stats, time_window, &mut header_written);

        drop(writer);
        let content = std::fs::read_to_string(&csv_file).unwrap();
        
        assert!(header_written);
        assert!(content.contains("src_ip,dest_ip,src_port,dest_port"));
        assert!(content.contains("192.168.1.1,192.168.1.2,8080,443"));
        assert!(content.contains("IPV4,TCP,OUTGOING,50,2500"));
    }

    // #[test]
    // fn test_write_csv_output_header_only_once() {
    //     let temp_dir = TempDir::new().unwrap();
    //     let csv_file = temp_dir.path().join("test.csv");
    //     let file = File::create(&csv_file).unwrap();
    //     let mut writer = BufWriter::new(&file);
    //     let mut header_written = false;

    //     // First write
    //     let stats = IndexMap::new();
    //     let time_window = Arc::new(Local::now());
    //     Reporter::write_csv_output(&mut writer, stats.clone(), time_window.clone(), &mut header_written);

    //     // Second write
    //     Reporter::write_csv_output(&mut writer, stats, time_window, &mut header_written);

    //     drop(writer);
    //     let content = std::fs::read_to_string(&csv_file).unwrap();
        
    //     // Header should only appear once
    //     let header_count = content.matches("src_ip,dest_ip,src_port,dest_port").count();
    //     assert_eq!(header_count, 1);
    // }

    // #[test]
    // fn test_throughput_params_initialization() {
    //     let start_time = Local::now();
    //     let outgoing_params = OutgoingDataThroughputParams::new(&start_time);

    //     assert_eq!(outgoing_params.time_in_seconds_since_start, 0);
    //     assert_eq!(outgoing_params.current_max_data_point, 0);
    //     assert_eq!(outgoing_params.previous_data_point, 0);
    //     assert_eq!(outgoing_params.largest_throughput_delta, 0);
    //     assert_eq!(outgoing_params.chart_update_time_interval_secs, 2);
    //     assert_eq!(outgoing_params.throughput_record.len(), 1);
    //     assert_eq!(outgoing_params.throughput_record[0], (0, 0));
    // }

    // #[test]
    // fn test_data_throughput_graph_generation() {
    //     let (reporter, _temp_dir) = create_temp_reporter(Some(4));
    //     let start_time = Local::now();
    //     let mut outgoing_params = OutgoingDataThroughputParams::new(&start_time);
    //     let mut incoming_params = IncomingDataThroughputParams::new(&start_time);

    //     // Simulate some data
    //     outgoing_params.current_max_data_point = 1000;
    //     incoming_params.current_max_data_point = 1500;

    //     let result = reporter.write_data_throughput_report(&mut outgoing_params, &mut incoming_params);
    //     assert!(result.is_ok());

    //     // Check that SVG file was created
    //     assert!(std::path::Path::new(&reporter.data_throughput_file).exists());

    //     // Read and verify SVG content contains expected elements
    //     let svg_content = std::fs::read_to_string(&reporter.data_throughput_file).unwrap();
    //     assert!(svg_content.contains("Outgoing Traffic Throughput"));
    //     assert!(svg_content.contains("Incoming Traffic Throughput"));
    //     assert!(svg_content.contains("bytes/s"));
    // }

    // #[test]
    // fn test_packet_throughput_graph_generation() {
    //     let (reporter, _temp_dir) = create_temp_reporter(Some(4));
    //     let start_time = Local::now();
    //     let mut outgoing_params = OutgoingPacketThroughputParams::new(&start_time);
    //     let mut incoming_params = IncomingPacketThroughputParams::new(&start_time);

    //     // Simulate some packet data
    //     outgoing_params.current_max_data_point = 100;
    //     incoming_params.current_max_data_point = 150;

    //     let result = reporter.write_packet_throughput_report(&mut outgoing_params, &mut incoming_params);
    //     assert!(result.is_ok());

    //     // Check that SVG file was created
    //     assert!(std::path::Path::new(&reporter.packet_throughput_file).exists());

    //     // Read and verify SVG content
    //     let svg_content = std::fs::read_to_string(&reporter.packet_throughput_file).unwrap();
    //     assert!(svg_content.contains("Outgoing Traffic Throughput: Packets/second"));
    //     assert!(svg_content.contains("Incoming Traffic Throughput: Packets/second"));
    // }

    // #[test]
    // fn test_reporter_start_with_immediate_stop() {
    //     let (reporter, _temp_dir) = create_temp_reporter(Some(4));
    //     let packet_info = create_sample_packet_info();
        
    //     let signaller = Arc::new(ReporterSignaller {
    //         mutex: Arc::new(Mutex::new(ReporterStatus::STOPPED)),
    //         condvar: Default::default(),
    //     });

    //     // This should exit immediately since status is STOPPED
    //     reporter.start(packet_info, signaller);

    //     // Verify CSV file has content
    //     let csv_path = std::fs::read_dir(&reporter.output_folder)
    //         .unwrap()
    //         .next()
    //         .unwrap()
    //         .unwrap()
    //         .path()
    //         .join("report.csv");
        
    //     let csv_content = std::fs::read_to_string(&csv_path).unwrap();
    //     assert!(csv_content.contains("src_ip,dest_ip"));
    //     assert!(csv_content.contains("192.168.1.1,192.168.1.2"));
    // }

    // #[test]
    // fn test_reporter_lifecycle() {
    //     let (reporter, _temp_dir) = create_temp_reporter(Some(4));
    //     let packet_info = create_sample_packet_info();
        
    //     let signaller = Arc::new(ReporterSignaller {
    //         mutex: Arc::new(Mutex::new(ReporterStatus::RUNNING)),
    //         condvar: Default::default(),
    //     });

    //     let signaller_clone = signaller.clone();
    //     let stopped = Arc::new(AtomicBool::new(false));
    //     let stopped_clone = stopped.clone();

    //     // Start reporter in separate thread
    //     let reporter_thread = thread::spawn(move || {
    //         reporter.start(packet_info, signaller_clone);
    //         stopped_clone.store(true, Ordering::SeqCst);
    //     });

    //     // Let it run briefly
    //     thread::sleep(Duration::from_millis(100));

    //     // Stop the reporter
    //     {
    //         let mut status = signaller.mutex.lock().unwrap();
    //         *status = ReporterStatus::STOPPED;
    //         signaller.condvar.notify_all();
    //     }

    //     // Wait for thread to complete
    //     reporter_thread.join().unwrap();
        
    //     // Verify it actually stopped
    //     assert!(stopped.load(Ordering::SeqCst));
    // }

    // #[test]
    // fn test_write_report_interval_logic() {
    //     let (reporter, _temp_dir) = create_temp_reporter(Some(4)); // interval = 2
    //     let mut packet_info = create_sample_packet_info();
    //     let mut header_written = false;
    //     let mut csv_interval_counter = 2; // At the interval threshold
    //     let csv_file = File::create(_temp_dir.path().join("test.csv")).unwrap();
    //     let mut buf_writer = BufWriter::new(&csv_file);
    //     let mut data_throughput_graph_error = String::new();
    //     let start_time = Local::now();
    //     let mut outgoing_data = OutgoingDataThroughputParams::new(&start_time);
    //     let mut incoming_data = IncomingDataThroughputParams::new(&start_time);
    //     let mut outgoing_packet = OutgoingPacketThroughputParams::new(&start_time);
    //     let mut incoming_packet = IncomingPacketThroughputParams::new(&start_time);

    //     reporter.write_report(
    //         &mut packet_info,
    //         &mut header_written,
    //         &mut csv_interval_counter,
    //         &mut buf_writer,
    //         false,
    //         &mut data_throughput_graph_error,
    //         &mut outgoing_data,
    //         &mut incoming_data,
    //         &mut outgoing_packet,
    //         &mut incoming_packet,
    //     );

    //     // Counter should be reset to 0 when at interval
    //     assert_eq!(csv_interval_counter, 0);
    //     assert!(header_written);
        
    //     // Packet mapping should be cleared after writing
    //     let packet_info_guard = packet_info.lock().unwrap();
    //     assert!(packet_info_guard.packet_mapping.is_empty());
    // }

    // #[test]
    // fn test_multiple_transport_protocols() {
    //     let temp_dir = TempDir::new().unwrap();
    //     let csv_file = temp_dir.path().join("test.csv");
    //     let file = File::create(&csv_file).unwrap();
    //     let mut writer = BufWriter::new(&file);
    //     let mut header_written = false;

    //     let mut stats = IndexMap::new();
        
    //     // TCP link
    //     let tcp_link = PacketLink {
    //         src_ip: "192.168.1.1".to_string(),
    //         dest_ip: "192.168.1.2".to_string(),
    //         src_port: 80,
    //         dest_port: 443,
    //         transport_protocol: TransportProtocol::TCP,
    //     };

    //     // UDP link
    //     let udp_link = PacketLink {
    //         src_ip: "10.0.0.1".to_string(),
    //         dest_ip: "10.0.0.2".to_string(),
    //         src_port: 53,
    //         dest_port: 8080,
    //         transport_protocol: TransportProtocol::UDP,
    //     };

    //     let tcp_stats = PacketLinkStats {
    //         ip_version: IpVersion::V4,
    //         traffic_direction: TrafficDirection::Outgoing,
    //         num_packets: 30,
    //         num_bytes: 2000,
    //         start_time: Local::now() - TimeDelta::seconds(5),
    //         end_time: Local::now(),
    //     };

    //     let udp_stats = PacketLinkStats {
    //         ip_version: IpVersion::V6,
    //         traffic_direction: TrafficDirection::Incoming,
    //         num_packets: 15,
    //         num_bytes: 800,
    //         start_time: Local::now() - TimeDelta::seconds(3),
    //         end_time: Local::now(),
    //     };

    //     stats.insert(tcp_link, tcp_stats);
    //     stats.insert(udp_link, udp_stats);

    //     let time_window = Arc::new(Local::now());
    //     Reporter::write_csv_output(&mut writer, stats, time_window, &mut header_written);

    //     drop(writer);
    //     let content = std::fs::read_to_string(&csv_file).unwrap();
        
    //     assert!(content.contains("TCP"));
    //     assert!(content.contains("UDP"));
    //     assert!(content.contains("V4"));
    //     assert!(content.contains("V6"));
    //     assert!(content.contains("Outgoing"));
    //     assert!(content.contains("Incoming"));
    // }


}
