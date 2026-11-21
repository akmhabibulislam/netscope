use clap::{Parser, Subcommand};
use comfy_table::{presets::UTF8_FULL, Cell, Color, Table};
use netscope_core::Protocol;
use netscope_dns::DnsInspector;
use netscope_network::{
    collector::NetworkCollector, diagnostics::DiagnosticsEngine, firewall::NetworkFirewall,
    investigation::Investigator, sniffer::LiveTrafficSniffer, speedtest::SpeedTestEngine,
    wifi::WifiScanner,
};
use netscope_security::SecurityRuleEngine;
use netscope_storage::StorageManager;

#[derive(Parser)]
#[command(name = "netscope")]
#[command(about = "NetScope: Cross-Distribution Linux Network Intelligence CLI", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Display network status summary
    Status,
    /// List detected network interfaces and active traffic stats
    Interfaces,
    /// Monitor live network traffic bandwidth
    Traffic {
        #[arg(short, long)]
        interface: Option<String>,
    },
    /// Inspect active network connections
    Connections {
        #[arg(short, long)]
        protocol: Option<String>,
        #[arg(short, long)]
        established_only: bool,
    },
    /// List processes currently using the network
    Processes,
    /// Query or test DNS resolution
    Dns {
        #[arg(short, long)]
        domain: Option<String>,
        #[arg(short, long, default_value = "A")]
        qtype: String,
    },
    /// Run network diagnostics (ping, route, tcp)
    Diagnostics {
        #[arg(long)]
        ping: Option<String>,
        #[arg(long)]
        tcp: Option<String>,
        #[arg(short, long, default_value_t = 80)]
        port: u16,
        #[arg(short, long)]
        routes: bool,
    },
    /// Show recent security alerts
    Alerts,
    /// Inspect Wi-Fi link parameters and RF signal
    Wifi,
    /// Run speed and throughput benchmark test
    Speedtest,
    /// Forensically investigate an IP address or hostname
    Investigate { target: String },
    /// Monitor live inbound & outbound raw network packets in real-time
    Sniff {
        #[arg(short, long, default_value_t = 15)]
        count: usize,
        #[arg(short, long)]
        interface: Option<String>,
    },
    /// Inspect active bidirectional network flows and session conversations
    Flows {
        #[arg(short, long, default_value_t = 3)]
        duration_secs: u64,
        #[arg(short, long)]
        interface: Option<String>,
    },
    /// Manage application-owned netfilter firewall rules and emergency killswitch
    Firewall {
        #[arg(long)]
        activate_killswitch: bool,
        #[arg(long)]
        deactivate_killswitch: bool,
        #[arg(long)]
        block: Option<String>,
        #[arg(long)]
        unblock: Option<String>,
    },
    /// Terminate an active TCP connection (requires privileges)
    Kill {
        #[arg(short, long)]
        src: String,
        #[arg(short, long)]
        dst: String,
    },
    /// Export historical data
    Export {
        #[arg(short, long, default_value = "csv")]
        format: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();
    let collector = NetworkCollector::new();

    match cli.command.unwrap_or(Commands::Status) {
        Commands::Status => {
            println!("NetScope Network Intelligence (Linux)\n");
            let ifaces = collector.poll_interfaces().await;
            let sample = collector.collect_bandwidth_sample().await;

            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["Property", "Value"]);

            let active_if = sample
                .active_interface
                .unwrap_or_else(|| "None".to_string());
            table.add_row(vec!["Active Interface", &active_if]);
            table.add_row(vec![
                "Current Download Speed",
                &format!("{:.2} Kbps", sample.rx_speed_bps / 1000.0),
            ]);
            table.add_row(vec![
                "Current Upload Speed",
                &format!("{:.2} Kbps", sample.tx_speed_bps / 1000.0),
            ]);
            table.add_row(vec!["Total Detected Interfaces", &ifaces.len().to_string()]);

            let conns = collector.poll_connections().await;
            table.add_row(vec!["Active Sockets", &conns.len().to_string()]);

            let resolvers = DnsInspector::get_system_resolvers();
            table.add_row(vec!["System DNS Resolvers", &resolvers.join(", ")]);

            let fw_backend = NetworkFirewall::detect_backend();
            table.add_row(vec!["Firewall Backend", &fw_backend.to_string()]);

            let fw_status = NetworkFirewall::dual_stack_status();
            table.add_row(vec!["Firewall Killswitch", &fw_status.state.to_string()]);

            let intel = netscope_security::ThreatIntel::new();
            table.add_row(vec![
                "Threat Intelligence Cache",
                &format!("{} active IoCs", intel.len()),
            ]);

            println!("{table}");
        }
        Commands::Interfaces => {
            let ifaces = collector.poll_interfaces().await;
            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec![
                "Interface",
                "Type",
                "State",
                "MAC",
                "IPv4",
                "Rx (Bytes)",
                "Tx (Bytes)",
            ]);

            for iface in ifaces {
                let ipv4 = iface.ipv4_addresses.join(", ");
                table.add_row(vec![
                    Cell::new(iface.name),
                    Cell::new(iface.if_type.to_string()),
                    Cell::new(iface.oper_state.to_string()).fg(if iface.is_up {
                        Color::Green
                    } else {
                        Color::Red
                    }),
                    Cell::new(iface.mac_address.unwrap_or_else(|| "-".to_string())),
                    Cell::new(if ipv4.is_empty() {
                        "-".to_string()
                    } else {
                        ipv4
                    }),
                    Cell::new(iface.stats.rx_bytes.to_string()),
                    Cell::new(iface.stats.tx_bytes.to_string()),
                ]);
            }
            println!("{table}");
        }
        Commands::Traffic { interface } => {
            let ifaces = collector.poll_interfaces().await;
            if let Some(ref target) = interface {
                if !ifaces.iter().any(|i| i.name == *target) {
                    let available: Vec<_> = ifaces.iter().map(|i| i.name.as_str()).collect();
                    anyhow::bail!(
                        "Interface '{}' not found. Available interfaces: {}",
                        target,
                        if available.is_empty() {
                            "none".to_string()
                        } else {
                            available.join(", ")
                        }
                    );
                }
            }

            println!(
                "Monitoring network bandwidth on {} (Press Ctrl+C to stop)...",
                interface.as_deref().unwrap_or("all interfaces")
            );

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            // First tick finishes immediately; consume it to align with 1-second cadence
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        println!("\nTraffic monitoring stopped.");
                        break;
                    }
                    _ = interval.tick() => {
                        let sample = collector.collect_bandwidth_sample_for(interface.as_deref()).await;
                        let rx_str = format_speed(sample.rx_speed_bps);
                        let tx_str = format_speed(sample.tx_speed_bps);

                        match (&interface, &sample.active_interface) {
                            (Some(target), None) => {
                                println!(
                                    "[{}] Interface '{}' is currently unavailable or disconnected (Rx: 0 B/s | Tx: 0 B/s)",
                                    sample.timestamp.format("%H:%M:%S"),
                                    target
                                );
                            }
                            (Some(target), Some(_)) => {
                                println!(
                                    "[{}] Rx: {:>10} | Tx: {:>10} (Interface: {})",
                                    sample.timestamp.format("%H:%M:%S"),
                                    rx_str,
                                    tx_str,
                                    target
                                );
                            }
                            (None, active) => {
                                println!(
                                    "[{}] Rx: {:>10} | Tx: {:>10} (Active: {})",
                                    sample.timestamp.format("%H:%M:%S"),
                                    rx_str,
                                    tx_str,
                                    active.as_deref().unwrap_or("aggregated")
                                );
                            }
                        }
                    }
                }
            }
        }
        Commands::Connections {
            protocol,
            established_only,
        } => {
            let mut conns = collector.poll_connections().await;
            if let Some(ref proto) = protocol {
                conns.retain(|c| c.protocol.to_string().eq_ignore_ascii_case(proto));
            }
            if established_only {
                conns.retain(|c| c.state == netscope_core::ConnectionState::Established);
            }

            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec![
                "Proto",
                "Local Address",
                "Remote Address",
                "State",
                "PID/Process",
            ]);

            for c in conns.into_iter().take(50) {
                let proc_str = c
                    .process
                    .as_ref()
                    .map(|p| format!("{}:{}", p.name, p.pid))
                    .unwrap_or_else(|| "-".to_string());
                table.add_row(vec![
                    c.protocol.to_string(),
                    format!("{}:{}", c.local_addr, c.local_port),
                    format!("{}:{}", c.remote_addr, c.remote_port),
                    c.state.to_string(),
                    proc_str,
                ]);
            }
            println!("{table}");
        }
        Commands::Processes => {
            let conns = collector.poll_connections().await;
            let mut proc_map: std::collections::HashMap<String, (u32, usize, Vec<Protocol>)> =
                std::collections::HashMap::new();

            for conn in conns {
                if let Some(p) = conn.process {
                    let entry = proc_map.entry(p.name).or_insert((p.pid, 0, Vec::new()));
                    entry.1 += 1;
                    if !entry.2.contains(&conn.protocol) {
                        entry.2.push(conn.protocol);
                    }
                }
            }

            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["PID", "Process Name", "Active Sockets", "Protocols"]);

            for (name, (pid, count, protos)) in proc_map {
                let proto_str = protos
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                table.add_row(vec![
                    Cell::new(pid.to_string()),
                    Cell::new(name),
                    Cell::new(count.to_string()),
                    Cell::new(proto_str),
                ]);
            }
            println!("{table}");
        }
        Commands::Dns { domain, qtype } => {
            let inspector = DnsInspector::new()?;
            if let Some(ref d) = domain {
                println!("Resolving {} ({qtype})...", d);
                match inspector.resolve(d, &qtype).await {
                    Ok(record) => {
                        println!("Result: {}", record.response.unwrap_or_default());
                        println!("Duration: {} ms", record.duration_ms.unwrap_or(0));
                        println!("Resolver: {}", record.resolver);
                    }
                    Err(e) => anyhow::bail!("DNS query failed: {}", e),
                }
            } else {
                let resolvers = DnsInspector::get_system_resolvers();
                println!("Configured DNS Resolvers: {}", resolvers.join(", "));
            }
        }
        Commands::Diagnostics {
            ping,
            tcp,
            port,
            routes,
        } => {
            if let Some(ref host) = ping {
                println!("Pinging {} (4 probes)...", host);
                let res = DiagnosticsEngine::ping_host(host, 4)?;
                println!(
                    "Packets: {}/{} received ({}% loss)",
                    res.received, res.transmitted, res.packet_loss_percent
                );
                if let Some(avg) = res.avg_latency_ms {
                    println!("Average Latency: {:.2} ms", avg);
                }
            } else if let Some(ref host) = tcp {
                println!("Probing TCP {}:{}...", host, port);
                let res =
                    DiagnosticsEngine::test_tcp_port(host, port, std::time::Duration::from_secs(3))
                        .await;
                println!(
                    "Reachable: {} (Latency: {:.2} ms)",
                    res.is_reachable,
                    res.latency_ms.unwrap_or(0.0)
                );
            } else if routes {
                let rts = DiagnosticsEngine::get_routing_table();
                println!(
                    "{:<18} {:<18} {:<18} {:<8} {:<8}",
                    "Destination", "Gateway", "Genmask", "Flags", "Iface"
                );
                println!("{}", "-".repeat(70));
                for r in rts {
                    println!(
                        "{:<18} {:<18} {:<18} {:<8} {:<8}",
                        r.destination, r.gateway, r.genmask, r.flags, r.interface
                    );
                }
            } else {
                println!("Specify --ping <host>, --tcp <host> --port <port>, or --routes");
            }
        }
        Commands::Alerts => {
            let conns = collector.poll_connections().await;
            let mut engine = SecurityRuleEngine::new(vec![], vec![]);
            let alerts = engine.evaluate_connections(&conns);

            if alerts.is_empty() {
                println!("No active security threats or heuristic anomalies detected.");
            } else {
                let mut table = Table::new();
                table.load_preset(UTF8_FULL);
                table.set_header(vec!["Severity", "Rule ID", "Title", "Message"]);

                for a in alerts {
                    let sev_cell = Cell::new(a.severity.to_string()).fg(match a.severity {
                        netscope_core::AlertSeverity::Critical => Color::Red,
                        netscope_core::AlertSeverity::High => Color::Red,
                        netscope_core::AlertSeverity::Medium => Color::Yellow,
                        _ => Color::Blue,
                    });
                    table.add_row(vec![
                        sev_cell,
                        Cell::new(a.rule_id),
                        Cell::new(a.title),
                        Cell::new(a.message),
                    ]);
                }
                println!("{table}");
            }
        }
        Commands::Wifi => {
            let ifaces = collector.poll_interfaces().await;
            let wifi_iface = ifaces.iter().find(|i| {
                i.if_type == netscope_core::InterfaceType::WiFi || i.name.starts_with("wl")
            });

            if let Some(iface) = wifi_iface {
                if let Some(details) = WifiScanner::get_wifi_details(&iface.name) {
                    println!("Wi-Fi Interface: {}", iface.name);
                    println!(
                        "SSID: {}",
                        details.ssid.unwrap_or_else(|| "Connected".to_string())
                    );
                    println!(
                        "BSSID: {}",
                        details.bssid.unwrap_or_else(|| "N/A".to_string())
                    );
                    println!("Signal RSSI: {:?} dBm", details.signal_dbm);
                    println!("Link Quality: {:?}", details.link_quality);
                    println!("Frequency: {:?} GHz", details.frequency_ghz);
                    println!("Tx Bitrate: {:?} Mbps", details.tx_bitrate_mbps);
                } else {
                    println!("Wi-Fi interface {} is idle or unassociated.", iface.name);
                }
            } else {
                println!("No active Wi-Fi hardware interface detected.");
            }
        }
        Commands::Speedtest => {
            println!("Executing network throughput and latency benchmark...");
            match SpeedTestEngine::run_benchmark().await {
                Ok(res) => {
                    println!("Server: {}", res.server);
                    println!("Latency: {:.2} ms", res.latency_ms);
                    println!("Jitter: {:.2} ms", res.jitter_ms);
                    println!("Download Throughput: {:.2} Mbps", res.download_mbps);
                    println!("Upload Throughput: {:.2} Mbps", res.upload_mbps);
                }
                Err(e) => anyhow::bail!("Speedtest failed: {}", e),
            }
        }
        Commands::Investigate { target } => {
            println!("Investigating target: {}...", target);
            let report = Investigator::investigate(&target).await;
            println!("Target: {}", report.query);
            println!(
                "Network: {}",
                if report.is_private {
                    "Private / Loopback"
                } else {
                    "Public Internet"
                }
            );
            println!("Resolved IPs: {}", report.resolved_ips.join(", "));
            println!(
                "Reverse DNS: {}",
                report.reverse_dns.unwrap_or_else(|| "None".to_string())
            );
            println!("Reputation Score: {}/100", report.reputation_score);
            println!(
                "ASN / Network: {}",
                report.asn.unwrap_or_else(|| "N/A".to_string())
            );
            println!(
                "Country / City: {}",
                report.country.unwrap_or_else(|| "N/A".to_string())
            );
        }
        Commands::Sniff { count, interface } => {
            if count == 0 {
                anyhow::bail!("Packet count target must be greater than 0");
            }

            println!(
                "Starting live packet sniffer stream on {} (target: {} packets, Ctrl+C to cancel)...",
                interface.as_deref().unwrap_or("all interfaces"),
                count
            );
            let sniffer = LiveTrafficSniffer::new();
            if let Err(e) = sniffer.start_capture_on(interface.as_deref()) {
                anyhow::bail!("Error initializing sniffer: {}", e);
            }

            // Wait up to 10 seconds or until requested count is reached
            let start_time = std::time::Instant::now();
            let mut captured = Vec::new();
            while start_time.elapsed() < std::time::Duration::from_secs(10) {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                let current = sniffer.get_recent_packets(count);
                if current.len() >= count || !sniffer.is_running() {
                    captured = current;
                    break;
                }
            }

            if captured.is_empty() {
                captured = sniffer.get_recent_packets(count);
            }

            if !sniffer.has_raw_permission() {
                sniffer.stop_capture();
                anyhow::bail!(
                    "AF_PACKET raw socket permission denied: CAP_NET_RAW capability required.\nGrant capability via: sudo setcap cap_net_raw,cap_net_admin+eip $(which netscope-cli)"
                );
            }

            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec![
                "Dir",
                "Proto",
                "Source",
                "Destination",
                "Bytes",
                "Summary",
            ]);

            for p in captured {
                let dir_cell = Cell::new(p.direction.to_string()).fg(match p.direction {
                    netscope_core::PacketDirection::Inbound => Color::Green,
                    netscope_core::PacketDirection::Outbound => Color::Red,
                });

                table.add_row(vec![
                    dir_cell,
                    Cell::new(p.protocol),
                    Cell::new(format!("{}:{}", p.src_addr, p.src_port.unwrap_or(0))),
                    Cell::new(format!("{}:{}", p.dst_addr, p.dst_port.unwrap_or(0))),
                    Cell::new(p.length_bytes.to_string()),
                    Cell::new(p.summary),
                ]);
            }
            println!("{table}");
            sniffer.stop_capture();
        }
        Commands::Flows {
            duration_secs,
            interface,
        } => {
            if duration_secs == 0 {
                anyhow::bail!("Flow observation duration must be greater than 0 seconds");
            }

            println!(
                "Monitoring live packets and aggregating session flows on {} for {} seconds...",
                interface.as_deref().unwrap_or("all interfaces"),
                duration_secs
            );
            let sniffer = LiveTrafficSniffer::new();
            if let Err(e) = sniffer.start_capture_on(interface.as_deref()) {
                anyhow::bail!("Error initializing sniffer: {}", e);
            }

            tokio::time::sleep(std::time::Duration::from_secs(duration_secs)).await;

            if !sniffer.has_raw_permission() {
                sniffer.stop_capture();
                anyhow::bail!(
                    "AF_PACKET raw socket permission denied: CAP_NET_RAW capability required.\nGrant capability via: sudo setcap cap_net_raw,cap_net_admin+eip $(which netscope-cli)"
                );
            }

            let flows = sniffer.get_active_flows();
            sniffer.stop_capture();

            if flows.is_empty() {
                println!("No active conversations/flows recorded during observation window.");
                return Ok(());
            }

            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec![
                "Proto",
                "State",
                "Endpoint A",
                "⇄",
                "Endpoint B",
                "Bytes",
                "Packets",
                "Duration",
            ]);

            for f in flows {
                let state_color = match f.state {
                    netscope_core::FlowState::Established => Color::Green,
                    netscope_core::FlowState::Closing | netscope_core::FlowState::Closed => {
                        Color::Yellow
                    }
                    _ => Color::Blue,
                };

                table.add_row(vec![
                    Cell::new(f.key.protocol.to_string()),
                    Cell::new(f.state.to_string()).fg(state_color),
                    Cell::new(format!("{}:{}", f.key.endpoint_a.0, f.key.endpoint_a.1)),
                    Cell::new("⇄"),
                    Cell::new(format!("{}:{}", f.key.endpoint_b.0, f.key.endpoint_b.1)),
                    Cell::new(format!("{:.1} KB", f.total_bytes() as f64 / 1024.0)),
                    Cell::new(f.total_packets().to_string()),
                    Cell::new(format!("{}s", f.duration_seconds())),
                ]);
            }
            println!("{table}");
        }
        Commands::Firewall {
            activate_killswitch,
            deactivate_killswitch,
            block,
            unblock,
        } => {
            let backend = NetworkFirewall::detect_backend();
            println!("Firewall Backend: {}", backend);

            if activate_killswitch {
                println!("Activating Emergency Kill-Switch (transactional rollback on failure)...");
                match NetworkFirewall::activate_emergency_killswitch() {
                    Ok(msg) => println!("[+] {}", msg),
                    Err(e) => anyhow::bail!("Failed to activate killswitch: {}", e),
                }
            } else if deactivate_killswitch {
                println!("Deactivating Emergency Kill-Switch...");
                match NetworkFirewall::deactivate_emergency_killswitch() {
                    Ok(msg) => println!("[+] {}", msg),
                    Err(e) => anyhow::bail!("Failed to deactivate killswitch: {}", e),
                }
            } else if let Some(ref ip) = block {
                match NetworkFirewall::block_ip(ip) {
                    Ok(msg) => println!("[+] {}", msg),
                    Err(e) => anyhow::bail!("Failed to block IP {}: {}", ip, e),
                }
            } else if let Some(ref ip) = unblock {
                match NetworkFirewall::unblock_ip(ip) {
                    Ok(msg) => println!("[+] {}", msg),
                    Err(e) => anyhow::bail!("Failed to unblock IP {}: {}", ip, e),
                }
            } else {
                let status = NetworkFirewall::dual_stack_status();
                println!("Emergency Killswitch State: {}", status.state);
                println!("IPv4 Active: {}", status.ipv4_active);
                println!("IPv6 Active: {}", status.ipv6_active);
            }
        }
        Commands::Kill { src, dst } => {
            println!("Attempting socket drop for {} -> {}...", src, dst);
            match NetworkFirewall::kill_connection(&src, &dst) {
                Ok(msg) => println!("[+] {}", msg),
                Err(e) => anyhow::bail!("Drop failed: {}", e),
            }
        }
        Commands::Export { format } => {
            let storage = StorageManager::new(None)?;
            if format.eq_ignore_ascii_case("csv") {
                let csv_data = storage.export_alerts_csv()?;
                println!("{csv_data}");
            } else {
                anyhow::bail!(
                    "Unsupported export format: '{}'. Supported formats: csv",
                    format
                );
            }
        }
    }

    Ok(())
}

fn format_speed(bps: f64) -> String {
    let bytes_per_sec = bps / 8.0;
    if bytes_per_sec >= 1_000_000_000.0 {
        format!("{:.2} GB/s", bytes_per_sec / 1_000_000_000.0)
    } else if bytes_per_sec >= 1_000_000.0 {
        format!("{:.2} MB/s", bytes_per_sec / 1_000_000.0)
    } else if bytes_per_sec >= 1_000.0 {
        format!("{:.2} KB/s", bytes_per_sec / 1_000.0)
    } else {
        format!("{:.0} B/s", bytes_per_sec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_speed() {
        assert_eq!(format_speed(0.0), "0 B/s");
        assert_eq!(format_speed(800.0), "100 B/s");
        assert_eq!(format_speed(8_000.0), "1.00 KB/s");
        assert_eq!(format_speed(80_000_000.0), "10.00 MB/s");
        assert_eq!(format_speed(8_000_000_000.0), "1.00 GB/s");
    }

    #[test]
    fn test_cli_parsing_traffic_interface() {
        let cli = Cli::try_parse_from(["netscope", "traffic", "--interface", "eth0"]).unwrap();
        match cli.command {
            Some(Commands::Traffic { interface }) => {
                assert_eq!(interface.as_deref(), Some("eth0"));
            }
            _ => panic!("Expected Traffic command"),
        }
    }

    #[test]
    fn test_cli_parsing_traffic_no_interface() {
        let cli = Cli::try_parse_from(["netscope", "traffic"]).unwrap();
        match cli.command {
            Some(Commands::Traffic { interface }) => {
                assert_eq!(interface, None);
            }
            _ => panic!("Expected Traffic command"),
        }
    }
}
