use clap::{Parser, Subcommand};
use comfy_table::{presets::UTF8_FULL, Cell, Color, Table};
use netscope_core::Protocol;
use netscope_dns::DnsInspector;
use netscope_network::{collector::NetworkCollector, diagnostics::DiagnosticsEngine, firewall::NetworkFirewall, investigation::Investigator, sniffer::LiveTrafficSniffer, speedtest::SpeedTestEngine, wifi::WifiScanner};
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
    Investigate {
        target: String,
    },
    /// Monitor live inbound & outbound raw network packets in real-time
    Sniff {
        #[arg(short, long, default_value_t = 15)]
        count: usize,
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

            let active_if = sample.active_interface.unwrap_or_else(|| "None".to_string());
            table.add_row(vec!["Active Interface", &active_if]);
            table.add_row(vec!["Current Download Speed", &format!("{:.2} Kbps", sample.rx_speed_bps / 1000.0)]);
            table.add_row(vec!["Current Upload Speed", &format!("{:.2} Kbps", sample.tx_speed_bps / 1000.0)]);
            table.add_row(vec!["Total Detected Interfaces", &ifaces.len().to_string()]);

            let conns = collector.poll_connections().await;
            table.add_row(vec!["Active Sockets", &conns.len().to_string()]);

            let resolvers = DnsInspector::get_system_resolvers();
            table.add_row(vec!["System DNS Resolvers", &resolvers.join(", ")]);

            println!("{table}");
        }
        Commands::Interfaces => {
            let ifaces = collector.poll_interfaces().await;
            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["Interface", "Type", "State", "MAC", "IPv4", "Rx (Bytes)", "Tx (Bytes)"]);

            for iface in ifaces {
                let ipv4 = iface.ipv4_addresses.join(", ");
                table.add_row(vec![
                    Cell::new(iface.name),
                    Cell::new(iface.if_type.to_string()),
                    Cell::new(iface.oper_state.to_string()).fg(if iface.is_up { Color::Green } else { Color::Red }),
                    Cell::new(iface.mac_address.unwrap_or_else(|| "-".to_string())),
                    Cell::new(if ipv4.is_empty() { "-".to_string() } else { ipv4 }),
                    Cell::new(iface.stats.rx_bytes.to_string()),
                    Cell::new(iface.stats.tx_bytes.to_string()),
                ]);
            }
            println!("{table}");
        }
        Commands::Traffic { interface: _ } => {
            println!("Monitoring live bandwidth (Ctrl+C to stop)...");
            for _ in 0..5 {
                tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                let sample = collector.collect_bandwidth_sample().await;
                println!(
                    "[{}] Rx: {:.2} Kbps | Tx: {:.2} Kbps | Total Rx: {} KB | Total Tx: {} KB",
                    sample.active_interface.as_deref().unwrap_or("any"),
                    sample.rx_speed_bps / 1000.0,
                    sample.tx_speed_bps / 1000.0,
                    sample.rx_bytes_total / 1024,
                    sample.tx_bytes_total / 1024
                );
            }
        }
        Commands::Connections { protocol, established_only } => {
            let mut conns = collector.poll_connections().await;
            if let Some(proto) = protocol {
                conns.retain(|c| c.protocol.to_string().eq_ignore_ascii_case(&proto));
            }
            if established_only {
                conns.retain(|c| c.state == netscope_core::ConnectionState::Established);
            }

            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["Proto", "Local Address", "Remote Address", "State", "PID", "Process"]);

            for conn in conns.iter().take(50) {
                let (pid, proc_name) = match &conn.process {
                    Some(p) => (p.pid.to_string(), p.name.clone()),
                    None => ("-".to_string(), "-".to_string()),
                };

                table.add_row(vec![
                    Cell::new(conn.protocol.to_string()),
                    Cell::new(format!("{}:{}", conn.local_addr, conn.local_port)),
                    Cell::new(format!("{}:{}", conn.remote_addr, conn.remote_port)),
                    Cell::new(conn.state.to_string()),
                    Cell::new(pid),
                    Cell::new(proc_name),
                ]);
            }
            println!("{table}");
            if conns.len() > 50 {
                println!("(Showing 50 of {} connections)", conns.len());
            }
        }
        Commands::Processes => {
            let conns = collector.poll_connections().await;
            let mut proc_map: std::collections::HashMap<String, (u32, usize, Vec<Protocol>)> = std::collections::HashMap::new();

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
                let proto_str = protos.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
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
            if let Some(d) = domain {
                println!("Querying DNS for {} (type {})...", d, qtype);
                match inspector.resolve(&d, &qtype).await {
                    Ok(rec) => {
                        println!("Resolver: {}", rec.resolver);
                        println!("Duration: {} ms", rec.duration_ms.unwrap_or(0));
                        println!("Response: {}", rec.response.unwrap_or_else(|| "None".to_string()));
                    }
                    Err(e) => println!("DNS Lookup failed: {}", e),
                }
            } else {
                let resolvers = DnsInspector::get_system_resolvers();
                println!("Configured DNS Resolvers: {}", resolvers.join(", "));
            }
        }
        Commands::Diagnostics { ping, tcp, port, routes } => {
            if let Some(target) = ping {
                println!("Pinging {}...", target);
                match DiagnosticsEngine::ping_host(&target, 4) {
                    Ok(res) => {
                        println!("Transmitted: {}, Received: {}, Loss: {}%", res.transmitted, res.received, res.packet_loss_percent);
                        if let (Some(min), Some(avg), Some(max)) = (res.min_latency_ms, res.avg_latency_ms, res.max_latency_ms) {
                            println!("Min/Avg/Max Latency: {:.2} / {:.2} / {:.2} ms", min, avg, max);
                        }
                    }
                    Err(e) => println!("Ping error: {}", e),
                }
            } else if let Some(target) = tcp {
                println!("Testing TCP connectivity to {}:{}...", target, port);
                let res = DiagnosticsEngine::test_tcp_port(&target, port, std::time::Duration::from_secs(3)).await;
                if res.is_reachable {
                    println!("Reachable! Latency: {:.2} ms", res.latency_ms.unwrap_or(0.0));
                } else {
                    println!("Failed: {}", res.error.unwrap_or_default());
                }
            } else if routes {
                let rts = DiagnosticsEngine::get_routing_table();
                let mut table = Table::new();
                table.load_preset(UTF8_FULL);
                table.set_header(vec!["Destination", "Gateway", "Genmask", "Flags", "Iface"]);
                for r in rts {
                    table.add_row(vec![r.destination, r.gateway, r.genmask, r.flags, r.interface]);
                }
                println!("{table}");
            } else {
                println!("Run with --help to see diagnostic options (e.g. --ping 1.1.1.1, --tcp google.com --port 443, --routes)");
            }
        }
        Commands::Alerts => {
            let mut engine = SecurityRuleEngine::new(vec![], vec![]);
            let conns = collector.poll_connections().await;
            let alerts = engine.evaluate_connections(&conns);

            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["Severity", "Rule", "Title", "Message"]);

            for a in alerts {
                table.add_row(vec![
                    Cell::new(a.severity.to_string()),
                    Cell::new(a.rule_id),
                    Cell::new(a.title),
                    Cell::new(a.message),
                ]);
            }
            println!("{table}");
        }
        Commands::Wifi => {
            let ifaces = collector.poll_interfaces().await;
            let wifi_iface = ifaces.iter().find(|i| i.if_type == netscope_core::InterfaceType::WiFi || i.name.starts_with("wl"));
            if let Some(iface) = wifi_iface {
                if let Some(details) = WifiScanner::get_wifi_details(&iface.name) {
                    let mut table = Table::new();
                    table.load_preset(UTF8_FULL);
                    table.set_header(vec!["Parameter", "Value"]);
                    table.add_row(vec!["Interface", &details.interface]);
                    table.add_row(vec!["SSID", &details.ssid.unwrap_or_else(|| "N/A".to_string())]);
                    table.add_row(vec!["BSSID", &details.bssid.unwrap_or_else(|| "N/A".to_string())]);
                    table.add_row(vec!["Signal RSSI", &format!("{} dBm", details.signal_dbm.map(|s| s.to_string()).unwrap_or_else(|| "-".to_string()))]);
                    table.add_row(vec!["Link Quality", &details.link_quality.unwrap_or_else(|| "-".to_string())]);
                    table.add_row(vec!["Frequency", &format!("{:.3} GHz", details.frequency_ghz.unwrap_or(0.0))]);
                    table.add_row(vec!["Bitrate", &format!("{:.1} Mbps", details.tx_bitrate_mbps.unwrap_or(0.0))]);
                    println!("{table}");
                } else {
                    println!("Wi-Fi interface {} is not connected or unassociated", iface.name);
                }
            } else {
                println!("No Wi-Fi interface detected on this machine");
            }
        }
        Commands::Speedtest => {
            println!("Benchmarking network performance (latency, jitter, download, upload)...");
            match SpeedTestEngine::run_benchmark().await {
                Ok(bench) => {
                    let mut table = Table::new();
                    table.load_preset(UTF8_FULL);
                    table.set_header(vec!["Benchmark Metric", "Result"]);
                    table.add_row(vec!["Target Server", &bench.server]);
                    table.add_row(vec!["Ping Latency", &format!("{:.2} ms", bench.latency_ms)]);
                    table.add_row(vec!["Jitter", &format!("{:.2} ms", bench.jitter_ms)]);
                    table.add_row(vec!["Download Throughput", &format!("{:.2} Mbps", bench.download_mbps)]);
                    table.add_row(vec!["Upload Throughput", &format!("{:.2} Mbps", bench.upload_mbps)]);
                    println!("{table}");
                }
                Err(e) => println!("Benchmark error: {}", e),
            }
        }
        Commands::Investigate { target } => {
            println!("Investigating target '{}'...", target);
            let rep = Investigator::investigate(&target).await;
            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["Property", "Details"]);
            table.add_row(vec!["Target Query", &rep.query]);
            table.add_row(vec!["Classification", if rep.is_private { "Private (RFC 1918)" } else { "Public Internet Target" }]);
            table.add_row(vec!["Reputation", &rep.reputation_score]);
            table.add_row(vec!["Resolved IPs", &rep.resolved_ips.join(", ")]);
            table.add_row(vec!["Reverse DNS", &rep.reverse_dns.unwrap_or_else(|| "None".to_string())]);
            table.add_row(vec!["Network ASN / Org", &rep.asn.unwrap_or_else(|| "Local Subnet".to_string())]);
            table.add_row(vec!["Country / Transit", &rep.country.unwrap_or_else(|| "Local".to_string())]);
            println!("{table}");
        }
        Commands::Sniff { count } => {
            println!("Starting live packet sniffer stream (observing inbound & outbound traffic)...");
            let sniffer = LiveTrafficSniffer::new();
            let _ = sniffer.start_capture();

            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            let packets = sniffer.get_recent_packets(count);

            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["Dir", "Proto", "Source", "Destination", "Bytes", "Summary"]);

            for p in packets {
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
        Commands::Kill { src, dst } => {
            println!("Attempting socket drop for {} -> {}...", src, dst);
            match NetworkFirewall::kill_connection(&src, &dst) {
                Ok(msg) => println!("{}", msg),
                Err(e) => println!("Drop failed: {}", e),
            }
        }
        Commands::Export { format } => {
            let storage = StorageManager::new(None)?;
            if format.eq_ignore_ascii_case("csv") {
                let csv_data = storage.export_alerts_csv()?;
                println!("{csv_data}");
            } else {
                println!("Supported formats: csv");
            }
        }
    }

    Ok(())
}
