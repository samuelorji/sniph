use crate::models::TransportProtocol;
use std::fmt::Display;

#[derive(Debug)]
pub struct PacketFilter {
    pub min_src_port: u16,
    pub max_src_port: u16,
    pub min_dst_port: u16,
    pub max_dst_port: u16,
    pub src_ip: Option<Either<String, String>>,
    pub dst_ip: Option<Either<String, String>>,
    pub transport_protocol: Option<Either<TransportProtocol, TransportProtocol>>,
}

#[derive(Debug)]
enum Either<A, B> {
    IS(A),
    NOT(B),
}

impl Display for PacketFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let empty_string = String::new();
        let src_ip_string = match self.src_ip {
            None => empty_string.clone(),
            Some(Either::IS(ref src_ip)) => format!("src_ip == {} ", &src_ip),
            Some(Either::NOT(ref src_ip)) => format!("src_ip != {} ", &src_ip),
        };
        let dst_ip_string = match self.dst_ip {
            None => empty_string.clone(),
            Some(Either::IS(ref dst_ip)) => format!("dst_ip == {} ", &dst_ip),
            Some(Either::NOT(ref dst_ip)) => format!("dst_ip != {} ", &dst_ip),
        };
        let transport_string = match self.transport_protocol {
            None => empty_string.clone(),
            Some(Either::IS(ref transport)) => format!("transport == {:?} ", &transport),
            Some(Either::NOT(ref transport)) => format!("transport != {:?} ", &transport),
        };

        write!(
            f,
            "Filters [ {}{}{}src_port >= {} src_port <= {} dst_port >= {} dst_port <= {} ]",
            src_ip_string,
            dst_ip_string,
            transport_string,
            self.min_src_port,
            self.max_src_port,
            self.min_dst_port,
            self.max_dst_port
        )
    }
}

impl PacketFilter {
    pub fn new(filter_string: &str) -> Result<PacketFilter, String> {
        let supported_fields = vec!["src_ip", "dst_ip", "src_port", "dst_port", "transport"];
        let supported_operators = vec![">", "<", ">=", "<=", "==", "!="];

        let filters: Vec<&str> = filter_string.split(',').map(|token| token.trim()).collect();

        if filters.len() > 10 {
            return Err(format!("Too many filters applied"));
        }

        let mut src_ip: Option<Either<String, String>> = None;
        let mut dst_ip: Option<Either<String, String>> = None;
        let mut min_src_port: u16 = 1;
        let mut max_src_port: u16 = 65535;
        let mut min_dst_port: u16 = 1;
        let mut max_dst_port: u16 = 65535;
        let mut transport_transport: Option<Either<TransportProtocol, TransportProtocol>> = None;

        for filter in filters {
            let parts: Vec<&str> = filter
                .split_whitespace()
                .map(|token| token.trim())
                .collect();
            if parts.len() != 3 {
                return Err(format!("Invalid filter format: {}", filter));
            }

            let field = parts[0];
            let operator = parts[1];
            let value = parts[2];

            if !supported_fields.contains(&field) {
                return Err(format!("Unsupported field in filter: {}", field));
            }

            if !supported_operators.contains(&operator) {
                return Err(format!("Unsupported operator in filter: {}", operator));
            }

            if value.len() >= 50 {
                return Err(format!("Invalid value length in filter: {}", value));
            }

            if operator == "==" || operator == "!=" {
                match field {
                    "src_ip" => {
                        if operator == "==" {
                            src_ip = Some(Either::IS(value.to_string()));
                        } else {
                            src_ip = Some(Either::NOT(value.to_string()));
                        }
                    }
                    "dst_ip" => {
                        if operator == "==" {
                            dst_ip = Some(Either::IS(value.to_string()));
                        } else {
                            dst_ip = Some(Either::NOT(value.to_string()));
                        }
                    }
                    "transport" => {
                        match value.to_lowercase().as_str() {
                            "tcp" => {
                                if operator == "==" {
                                    transport_transport = Some(Either::IS(TransportProtocol::TCP))
                                } else {
                                    transport_transport = Some(Either::NOT(TransportProtocol::TCP))
                                }
                            }
                            "udp" => {
                                if operator == "==" {
                                    transport_transport = Some(Either::IS(TransportProtocol::UDP))
                                } else {
                                    transport_transport = Some(Either::NOT(TransportProtocol::UDP))
                                }
                            }

                            _ => return Err(format!("Unsupported transport: {}", value)),
                        };
                    }
                    _ => {
                        return Err(format!(
                            "Field {} does not support operator {}",
                            field, operator
                        ));
                    }
                }
            } else {
                match field {
                    x @ ("src_port" | "dst_port") => {
                        if let Ok(port) = value.parse::<u16>() {
                            let is_src_port = x == "src_port";
                            match operator {
                                ">=" => {
                                    if is_src_port {
                                        min_src_port = port
                                    } else {
                                        min_dst_port = port
                                    }
                                }
                                "<=" => {
                                    if is_src_port {
                                        max_src_port = port
                                    } else {
                                        max_dst_port = port
                                    }
                                }
                                ">" => {
                                    if port >= 65535 {
                                        return Err(format!(
                                            "Max port cannot be greater than 65535"
                                        ));
                                    }
                                    if is_src_port {
                                        min_src_port = port + 1;
                                    } else {
                                        min_dst_port = port + 1;
                                    }
                                }
                                "<" => {
                                    if port < 1 {
                                        return Err(format!("Minimum port cannot be less than 1"));
                                    }
                                    if is_src_port {
                                        max_src_port = port - 1;
                                    } else {
                                        max_dst_port = port - 1;
                                    }
                                }

                                _ => return Err(format!("Unsupported operator: {}", operator)),
                            }

                            if min_src_port > max_src_port || min_dst_port > max_dst_port {
                                return Err(format!(
                                    "minimum source or destination port cannot be greater than maximum source or destination port"
                                ));
                            }

                            if min_src_port < 1 || min_dst_port < 1 {
                                return Err(format!(
                                    "minimum source or destination port cannot be less than 1"
                                ));
                            }
                        } else {
                            return Err(format!("Invalid port number: {}", value));
                        }
                    }
                    _ => {
                        return Err(format!(
                            "Field {} does not support operator {}",
                            field, operator
                        ));
                    }
                }
            }
        }

        Ok(PacketFilter {
            min_src_port,
            max_src_port,
            min_dst_port,
            max_dst_port,
            src_ip,
            dst_ip,
            transport_protocol: transport_transport,
        })
    }

    pub fn should_capture_with_ports(&self, src_port: u16, dst_port: u16) -> bool {
        src_port <= self.max_src_port
            && src_port >= self.min_src_port
            && dst_port <= self.max_dst_port
            && dst_port >= self.min_dst_port
    }

    pub fn should_capture_with_ips(&self, src_ip: &str, dst_ip: &str) -> bool {
        let should_skip_src_ip = if let Some(either) = &self.src_ip {
            match either {
                Either::IS(x) => x == src_ip,
                Either::NOT(x) => x != src_ip,
            }
        } else {
            true
        };
        let should_skip_dst_ip = if let Some(either) = &self.dst_ip {
            match either {
                Either::IS(x) => dst_ip == x,
                Either::NOT(x) => dst_ip != x,
            }
        } else {
            true
        };
        should_skip_src_ip && should_skip_dst_ip
    }

    pub fn should_capture_with_transport(&self, transport_transport: TransportProtocol) -> bool {
        if let Some(either) = &self.transport_protocol {
            match either {
                Either::IS(x) => *x == transport_transport,
                Either::NOT(x) => *x != transport_transport,
            }
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_single_src_ip_filter() {
        let result = PacketFilter::new("src_ip == 192.168.1.1").unwrap();

        assert!(matches!(
            result,
            PacketFilter {
                src_ip: Some(Either::IS(_)),
                ..
            }
        ));

        match &result.src_ip {
            Some(Either::IS(ip)) => assert_eq!(ip, "192.168.1.1"),
            _ => panic!("Expected src_ip to be IS(192.168.1.1)"),
        }
        assert!(result.dst_ip.is_none());
        assert!(result.transport_protocol.is_none());
    }

    #[test]
    fn test_valid_single_dst_ip_filter() {
        let result = PacketFilter::new("dst_ip != 10.0.0.1").unwrap();
        match &result.dst_ip {
            Some(Either::NOT(ip)) => assert_eq!(ip, "10.0.0.1"),
            _ => panic!("Expected dst_ip to be NOT(10.0.0.1)"),
        }
        assert!(result.src_ip.is_none());
        assert!(result.transport_protocol.is_none());
    }

    #[test]
    fn test_valid_src_port_range() {
        let result = PacketFilter::new("src_port >= 1024, src_port <= 65535").unwrap();
        assert_eq!(result.min_src_port, 1024);
        assert_eq!(result.max_src_port, 65535);
        assert_eq!(result.min_dst_port, 1);
        assert_eq!(result.max_dst_port, 65535);
    }

    #[test]
    fn test_valid_dst_port_range() {
        let result = PacketFilter::new("dst_port > 80, dst_port < 443").unwrap();
        assert_eq!(result.min_dst_port, 81);
        assert_eq!(result.max_dst_port, 442);
        assert_eq!(result.min_src_port, 1);
        assert_eq!(result.max_src_port, 65535);
    }

    #[test]
    fn test_valid_tcp_transport_filter() {
        let result = PacketFilter::new("transport == tcp").unwrap();
        match &result.transport_protocol {
            Some(Either::IS(TransportProtocol::TCP)) => {}
            _ => panic!("Expected transport to be IS(TCP)"),
        }
    }

    #[test]
    fn test_valid_udp_transport_filter() {
        let result = PacketFilter::new("transport != UDP").unwrap();
        match &result.transport_protocol {
            Some(Either::NOT(TransportProtocol::UDP)) => {}
            _ => panic!("Expected transport to be NOT(UDP)"),
        }
    }

    #[test]
    fn test_valid_complex_filter() {
        let result =
            PacketFilter::new("src_ip == 192.168.1.1, dst_port >= 80, transport == tcp").unwrap();

        match &result.src_ip {
            Some(Either::IS(ip)) => assert_eq!(ip, "192.168.1.1"),
            _ => panic!("Expected src_ip to be IS(192.168.1.1)"),
        }

        assert_eq!(result.min_dst_port, 80);
        assert_eq!(result.max_dst_port, 65535);

        match &result.transport_protocol {
            Some(Either::IS(TransportProtocol::TCP)) => {}
            _ => panic!("Expected transport to be IS(TCP)"),
        }
    }

    #[test]
    fn test_port_boundary_values() {
        let result = PacketFilter::new("src_port >= 1, src_port <= 65535").unwrap();
        assert_eq!(result.min_src_port, 1);
        assert_eq!(result.max_src_port, 65535);
    }

    #[test]
    fn test_port_increment_decrement_edge_case() {
        let result = PacketFilter::new("src_port > 65534").unwrap();
        assert_eq!(result.min_src_port, 65535);
        assert_eq!(result.max_src_port, 65535);
    }

    #[test]
    fn test_port_decrement_underflow_edge_case() {
        let result = PacketFilter::new("src_port < 2").unwrap();
        assert_eq!(result.min_src_port, 1);
        assert_eq!(result.max_src_port, 1);
    }

    #[test]
    fn test_case_insensitive_transport_tcp() {
        let result = PacketFilter::new("transport == TCP").unwrap();
        match &result.transport_protocol {
            Some(Either::IS(TransportProtocol::TCP)) => {}
            _ => panic!("Expected transport to be IS(TCP)"),
        }
    }

    #[test]
    fn test_case_insensitive_transport_udp() {
        let result = PacketFilter::new("transport != udp").unwrap();
        match &result.transport_protocol {
            Some(Either::NOT(TransportProtocol::UDP)) => {}
            _ => panic!("Expected transport to be NOT(UDP)"),
        }
    }

    #[test]
    fn test_mixed_case_transport() {
        let result = PacketFilter::new("transport == TcP").unwrap();
        match &result.transport_protocol {
            Some(Either::IS(TransportProtocol::TCP)) => {}
            _ => panic!("Expected transport to be IS(TCP)"),
        }
    }

    #[test]
    fn test_max_port_too_high() {
        let result = PacketFilter::new("src_port > 65535");
        assert!(result.is_err());

        let result = PacketFilter::new("src_port >= 65536");
        assert!(result.is_err());

        let result = PacketFilter::new("dst_port > 65535");
        assert!(result.is_err());

        let result = PacketFilter::new("dst_port >= 65536");
        assert!(result.is_err());
    }

    #[test]
    fn test_min_port_too_low() {
        let result = PacketFilter::new("src_port < 1");
        assert!(result.is_err());

        let result = PacketFilter::new("src_port < 0");
        assert!(result.is_err());

        let result = PacketFilter::new("src_port <= 0");
        assert!(result.is_err());

        let result = PacketFilter::new("dst_port < 1");
        assert!(result.is_err());

        let result = PacketFilter::new("dst_port < 0");
        assert!(result.is_err());

        let result = PacketFilter::new("dst_port <= 0");
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv6_address() {
        let result = PacketFilter::new("src_ip == 2001:db8::1").unwrap();
        match &result.src_ip {
            Some(Either::IS(ip)) => assert_eq!(ip, "2001:db8::1"),
            _ => panic!("Expected src_ip to be IS(2001:db8::1)"),
        }
    }

    #[test]
    fn test_zero_port_value() {
        let result = PacketFilter::new("src_port >= 1").unwrap();
        assert_eq!(result.min_src_port, 1);
        assert_eq!(result.max_src_port, 65535);
    }

    #[test]
    fn test_maximum_port_value() {
        let result = PacketFilter::new("dst_port <= 65535").unwrap();
        assert_eq!(result.min_dst_port, 1);
        assert_eq!(result.max_dst_port, 65535);
    }

    #[test]
    fn test_multiple_same_field_filters() {
        let result = PacketFilter::new("src_port >= 1024, src_port <= 8080").unwrap();
        assert_eq!(result.min_src_port, 1024);
        assert_eq!(result.max_src_port, 8080);
    }

    #[test]
    fn test_conflicting_transport_filters() {
        let result = PacketFilter::new("transport == tcp, transport != udp").unwrap();
        // Last filter should win
        match &result.transport_protocol {
            Some(Either::NOT(TransportProtocol::UDP)) => {}
            _ => panic!("Expected transport to be NOT(UDP)"),
        }
    }

    #[test]
    fn test_last_filter_wins() {
        let result = PacketFilter::new("src_ip == 192.168.1.1, src_ip == 1.1.1.1").unwrap();
        match &result.src_ip {
            Some(Either::IS(ip)) => assert_eq!(ip, "1.1.1.1"),
            _ => panic!("Expected src_ip to be IS(192.168.1.1)"),
        }
    }

    #[test]
    fn test_all_fields_combined() {
        let result = PacketFilter::new("src_ip == 192.168.1.1, dst_ip != 10.0.0.1, src_port >= 1024, dst_port <= 8080, transport == tcp").unwrap();

        match &result.src_ip {
            Some(Either::IS(ip)) => assert_eq!(ip, "192.168.1.1"),
            _ => panic!("Expected src_ip to be IS(192.168.1.1)"),
        }

        match &result.dst_ip {
            Some(Either::NOT(ip)) => assert_eq!(ip, "10.0.0.1"),
            _ => panic!("Expected dst_ip to be NOT(10.0.0.1)"),
        }

        assert_eq!(result.min_src_port, 1024);
        assert_eq!(result.max_src_port, 65535);
        assert_eq!(result.min_dst_port, 1);
        assert_eq!(result.max_dst_port, 8080);

        match &result.transport_protocol {
            Some(Either::IS(TransportProtocol::TCP)) => {}
            _ => panic!("Expected transport to be IS(TCP)"),
        }
    }

    #[test]
    fn test_localhost_ip() {
        let result = PacketFilter::new("src_ip == 127.0.0.1").unwrap();
        match &result.src_ip {
            Some(Either::IS(ip)) => assert_eq!(ip, "127.0.0.1"),
            _ => panic!("Expected src_ip to be IS(127.0.0.1)"),
        }
    }

    #[test]
    fn test_broadcast_ip() {
        let result = PacketFilter::new("dst_ip == 255.255.255.255").unwrap();
        match &result.dst_ip {
            Some(Either::IS(ip)) => assert_eq!(ip, "255.255.255.255"),
            _ => panic!("Expected dst_ip to be IS(255.255.255.255)"),
        }
    }

    #[test]
    fn test_private_network_ranges() {
        let result = PacketFilter::new("src_ip == 10.0.0.0, dst_ip == 172.16.0.0").unwrap();

        match &result.src_ip {
            Some(Either::IS(ip)) => assert_eq!(ip, "10.0.0.0"),
            _ => panic!("Expected src_ip to be IS(10.0.0.0)"),
        }

        match &result.dst_ip {
            Some(Either::IS(ip)) => assert_eq!(ip, "172.16.0.0"),
            _ => panic!("Expected dst_ip to be IS(172.16.0.0)"),
        }
    }

    #[test]
    fn test_port_overflow_edge_case() {
        let result = PacketFilter::new("src_port > 1").unwrap();
        assert_eq!(result.min_src_port, 2);
        assert_eq!(result.max_src_port, 65535);
    }

    #[test]
    fn test_port_underflow_edge_case() {
        let result = PacketFilter::new("dst_port < 65535").unwrap();
        assert_eq!(result.min_dst_port, 1);
        assert_eq!(result.max_dst_port, 65534);
    }

    #[test]
    fn test_exact_port_boundaries() {
        let result = PacketFilter::new("src_port >= 2, dst_port <= 65534").unwrap();
        assert_eq!(result.min_src_port, 2);
        assert_eq!(result.max_src_port, 65535);
        assert_eq!(result.min_dst_port, 1);
        assert_eq!(result.max_dst_port, 65534);
    }

    #[test]
    fn test_invalid_filter_format_missing_operator() {
        let result = PacketFilter::new("src_ip 192.168.1.1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid filter format"));
    }

    #[test]
    fn test_invalid_filter_format_too_many_parts() {
        let result = PacketFilter::new("src_ip == 192.168.1.1 extra");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid filter format"));
    }

    #[test]
    fn test_invalid_filter_format_empty() {
        let result = PacketFilter::new("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid filter format"));
    }

    #[test]
    fn test_unsupported_field() {
        let result = PacketFilter::new("invalid_field == value");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported field"));
    }

    #[test]
    fn test_unsupported_operator() {
        let result = PacketFilter::new("src_ip ~ 192.168.1.1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported operator"));
    }

    #[test]
    fn test_value_length_too_long() {
        let long_value = "a".repeat(50);
        let filter = format!("src_ip == {}", long_value);
        let result = PacketFilter::new(&filter);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid value length"));
    }

    #[test]
    fn test_unsupported_transport() {
        let result = PacketFilter::new("transport == http");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported transport"));
    }

    #[test]
    fn test_invalid_port_number() {
        let result = PacketFilter::new("src_port >= invalid_port");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid port number"));
    }

    #[test]
    fn test_port_number_too_large() {
        let result = PacketFilter::new("src_port >= 70000");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid port number"));
    }

    #[test]
    fn test_incompatible_operator_with_ip_field() {
        let result = PacketFilter::new("src_ip >= 192.168.1.1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not support operator"));
    }

    #[test]
    fn test_incompatible_operator_with_transport_field() {
        let result = PacketFilter::new("transport > tcp");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not support operator"));
    }

    #[test]
    fn test_incompatible_equality_operator_with_port() {
        let result = PacketFilter::new("src_port == 80");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not support operator"));
    }

    #[test]
    fn test_negative_port_comparison() {
        let result = PacketFilter::new("src_port >= -1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid port number"));
    }

    #[test]
    fn test_empty_value() {
        let result = PacketFilter::new("src_ip == ");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid filter format"));
    }

    // Tests for should_capture_with_ports method
    #[test]
    fn test_should_capture_with_ports_within_range() {
        let filter = PacketFilter::new(
            "src_port >= 1024, src_port <= 8080, dst_port >= 80, dst_port <= 443",
        )
        .unwrap();
        assert!(filter.should_capture_with_ports(2048, 80));
        assert!(filter.should_capture_with_ports(1024, 443));
        assert!(filter.should_capture_with_ports(8080, 100));
        assert!(!filter.should_capture_with_ports(1023, 100));
        assert!(!filter.should_capture_with_ports(1024, 445));
    }

    #[test]
    fn test_should_capture_with_ports_outside_range() {
        let filter = PacketFilter::new(
            "src_port >= 1024, src_port <= 8080, dst_port >= 80, dst_port <= 443",
        )
        .unwrap();
        assert!(!filter.should_capture_with_ports(1023, 80));
        assert!(!filter.should_capture_with_ports(8081, 80));
        assert!(!filter.should_capture_with_ports(2048, 79));
        assert!(!filter.should_capture_with_ports(2048, 444));
        assert!(!filter.should_capture_with_ports(1023, 444));
    }

    #[test]
    fn test_should_capture_with_ports_boundary_values() {
        let filter =
            PacketFilter::new("src_port >= 1, src_port <= 65535, dst_port >= 1, dst_port <= 65535")
                .unwrap();
        assert!(filter.should_capture_with_ports(1, 1));
        assert!(filter.should_capture_with_ports(65535, 65535));
        assert!(filter.should_capture_with_ports(32768, 32768));
    }

    #[test]
    fn test_should_capture_with_ports_single_port() {
        let filter =
            PacketFilter::new("src_port >= 80, src_port <= 80, dst_port >= 443, dst_port <= 443")
                .unwrap();
        assert!(filter.should_capture_with_ports(80, 443));
        assert!(!filter.should_capture_with_ports(80, 444));
        assert!(!filter.should_capture_with_ports(81, 443));
    }

    #[test]
    fn test_should_capture_with_ports_default_range() {
        let filter = PacketFilter::new("transport == tcp").unwrap();
        // Should capture any port since no port filters specified (defaults to 1-65535)
        assert!(filter.should_capture_with_ports(1, 1));
        assert!(filter.should_capture_with_ports(65535, 65535));
        assert!(filter.should_capture_with_ports(8080, 443));
    }

    // Tests for should_capture_with_ips method
    #[test]
    fn test_should_capture_with_ips_both_match_is() {
        let filter = PacketFilter::new("src_ip == 192.168.1.1, dst_ip == 10.0.0.1").unwrap();
        assert!(filter.should_capture_with_ips("192.168.1.1", "10.0.0.1"));
        assert!(!filter.should_capture_with_ips("192.168.1.2", "10.0.0.1"));
        assert!(!filter.should_capture_with_ips("192.168.1.1", "10.0.0.2"));
        assert!(!filter.should_capture_with_ips("192.168.1.2", "10.0.0.2"));
    }

    #[test]
    fn test_should_capture_with_ips_both_match_not() {
        let filter = PacketFilter::new("src_ip != 192.168.1.1, dst_ip != 10.0.0.1").unwrap();
        assert!(filter.should_capture_with_ips("192.168.1.2", "10.0.0.2"));
        assert!(!filter.should_capture_with_ips("192.168.1.1", "10.0.0.2"));
        assert!(!filter.should_capture_with_ips("192.168.1.2", "10.0.0.1"));
        assert!(!filter.should_capture_with_ips("192.168.1.1", "10.0.0.1"));
    }

    #[test]
    fn test_should_capture_with_ips_mixed_is_not() {
        let filter = PacketFilter::new("src_ip == 192.168.1.1, dst_ip != 10.0.0.1").unwrap();
        assert!(filter.should_capture_with_ips("192.168.1.1", "10.0.0.2"));
        assert!(!filter.should_capture_with_ips("192.168.1.1", "10.0.0.1"));
        assert!(!filter.should_capture_with_ips("192.168.1.2", "10.0.0.2"));
        assert!(!filter.should_capture_with_ips("192.168.1.2", "10.0.0.1"));
    }

    #[test]
    fn test_should_capture_with_ips_only_src_ip() {
        let filter = PacketFilter::new("src_ip == 192.168.1.1").unwrap();
        assert!(filter.should_capture_with_ips("192.168.1.1", "1.1.1.1"));
        assert!(!filter.should_capture_with_ips("192.168.1.2", "1.1.1.2"));
    }

    #[test]
    fn test_should_capture_with_ips_only_dst_ip() {
        let filter = PacketFilter::new("dst_ip != 10.0.0.1").unwrap();
        assert!(filter.should_capture_with_ips("192.168.1.1", "10.0.0.2"));
        assert!(!filter.should_capture_with_ips("192.168.1.2", "10.0.0.1"));
    }

    #[test]
    fn test_should_capture_with_ips_ipv6() {
        let filter = PacketFilter::new("src_ip == 2001:db8::1, dst_ip == 2001:db8::2").unwrap();
        assert!(filter.should_capture_with_ips("2001:db8::1", "2001:db8::2"));
        assert!(!filter.should_capture_with_ips("2001:db8::1", "2001:db8::3"));
    }

    #[test]
    fn test_should_capture_with_ips_localhost() {
        let filter = PacketFilter::new("src_ip == 127.0.0.1, dst_ip == 127.0.0.1").unwrap();
        assert!(filter.should_capture_with_ips("127.0.0.1", "127.0.0.1"));
        assert!(!filter.should_capture_with_ips("127.0.0.1", "127.0.0.2"));
    }

    #[test]
    fn test_should_capture_with_ips_empty_strings() {
        let filter = PacketFilter::new("src_ip == , dst_ip == ").unwrap_err();
        assert!(filter.contains("Invalid filter format"));
    }

    // Tests for should_capture_with_transport method
    #[test]
    fn test_should_capture_with_transport_tcp_match() {
        let filter = PacketFilter::new("transport == tcp").unwrap();
        assert!(filter.should_capture_with_transport(TransportProtocol::TCP));
        assert!(!filter.should_capture_with_transport(TransportProtocol::UDP));
    }

    #[test]
    fn test_should_capture_with_transport_udp_match() {
        let filter = PacketFilter::new("transport == udp").unwrap();
        assert!(filter.should_capture_with_transport(TransportProtocol::UDP));
        assert!(!filter.should_capture_with_transport(TransportProtocol::TCP));
    }

    #[test]
    fn test_should_capture_with_transport_tcp_not_match() {
        let filter = PacketFilter::new("transport != tcp").unwrap();
        assert!(!filter.should_capture_with_transport(TransportProtocol::TCP));
        assert!(filter.should_capture_with_transport(TransportProtocol::UDP));
    }

    #[test]
    fn test_should_capture_with_transport_udp_not_match() {
        let filter = PacketFilter::new("transport != udp").unwrap();
        assert!(filter.should_capture_with_transport(TransportProtocol::TCP));
        assert!(!filter.should_capture_with_transport(TransportProtocol::UDP));
    }

    #[test]
    fn test_should_capture_with_transport_no_filter() {
        let filter = PacketFilter::new("src_port >= 80").unwrap();
        // Should return false since no transport filter is set
        assert!(filter.should_capture_with_transport(TransportProtocol::TCP));
        assert!(filter.should_capture_with_transport(TransportProtocol::UDP));
    }

    // Integration tests combining all methods
    #[test]
    fn test_full_packet_filtering_tcp() {
        let filter = PacketFilter::new("src_ip == 192.168.1.1, dst_ip == 10.0.0.1, src_port >= 1024, dst_port >= 80, dst_port <= 443, transport == tcp").unwrap();

        // All conditions match
        assert!(filter.should_capture_with_ips("192.168.1.1", "10.0.0.1"));
        assert!(filter.should_capture_with_ports(2048, 80));
        assert!(filter.should_capture_with_transport(TransportProtocol::TCP));

        // Some conditions don't match
        assert!(!filter.should_capture_with_ips("192.168.1.2", "10.0.0.1"));
        assert!(!filter.should_capture_with_ports(1023, 80));
        assert!(!filter.should_capture_with_transport(TransportProtocol::UDP));
    }

    #[test]
    fn test_full_packet_filtering_udp_negation() {
        let filter = PacketFilter::new("src_ip != 192.168.1.1, dst_ip != 10.0.0.1, src_port > 1024, dst_port < 8080, transport != tcp").unwrap();

        // All conditions match (NOT cases)
        assert!(filter.should_capture_with_ips("192.168.1.2", "10.0.0.2"));
        assert!(filter.should_capture_with_ports(2048, 4000));
        assert!(filter.should_capture_with_transport(TransportProtocol::UDP));

        // Some conditions don't match
        assert!(!filter.should_capture_with_ips("192.168.1.1", "10.0.0.2"));
        assert!(!filter.should_capture_with_ports(1024, 4000));
        assert!(!filter.should_capture_with_transport(TransportProtocol::TCP));
    }

    #[test]
    fn test_port_filtering_edge_case_wrap_around() {
        let filter = PacketFilter::new("src_port > 65534").unwrap();
        assert!(filter.should_capture_with_ports(65535, 1));
        assert!(!filter.should_capture_with_ports(65534, 1));
    }

    #[test]
    fn test_port_filtering_edge_case_minimum() {
        let filter = PacketFilter::new("dst_port < 2").unwrap();
        assert!(filter.should_capture_with_ports(1, 1));
        assert!(!filter.should_capture_with_ports(1, 2));
    }

    #[test]
    fn test_ip_case_sensitivity() {
        let filter = PacketFilter::new("src_ip == Example.Com, dst_ip == LOCALHOST").unwrap();
        assert!(filter.should_capture_with_ips("Example.Com", "LOCALHOST"));
        assert!(!filter.should_capture_with_ips("example.com", "localhost"));
        assert!(!filter.should_capture_with_ips("EXAMPLE.COM", "LOCALHOST"));
    }

    #[test]
    fn test_combined_port_ranges_complex() {
        let filter =
            PacketFilter::new("src_port >= 8000, src_port <= 9000, dst_port > 20, dst_port < 25")
                .unwrap();
        assert!(filter.should_capture_with_ports(8500, 22));
        assert!(filter.should_capture_with_ports(8000, 24));
        assert!(filter.should_capture_with_ports(9000, 21));
        assert!(!filter.should_capture_with_ports(7999, 22));
        assert!(!filter.should_capture_with_ports(8500, 20));
        assert!(!filter.should_capture_with_ports(8500, 25));
    }
}
