use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResult {
    pub target: String,
    pub transmitted: u32,
    pub received: u32,
    pub min_latency_ms: Option<f64>,
    pub avg_latency_ms: Option<f64>,
    pub max_latency_ms: Option<f64>,
    pub packet_loss_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpTestResult {
    pub host: String,
    pub port: u16,
    pub is_reachable: bool,
    pub latency_ms: Option<f64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    pub destination: String,
    pub gateway: String,
    pub genmask: String,
    pub flags: String,
    pub interface: String,
}

pub struct DiagnosticsEngine;

impl DiagnosticsEngine {
    pub async fn test_tcp_port(host: &str, port: u16, timeout_duration: Duration) -> TcpTestResult {
        let addr_str = format!("{}:{}", host, port);
        let start = std::time::Instant::now();

        match timeout(timeout_duration, TcpStream::connect(&addr_str)).await {
            Ok(Ok(_stream)) => {
                let latency = start.elapsed().as_secs_f64() * 1000.0;
                TcpTestResult {
                    host: host.to_string(),
                    port,
                    is_reachable: true,
                    latency_ms: Some(latency),
                    error: None,
                }
            }
            Ok(Err(e)) => TcpTestResult {
                host: host.to_string(),
                port,
                is_reachable: false,
                latency_ms: None,
                error: Some(e.to_string()),
            },
            Err(_) => TcpTestResult {
                host: host.to_string(),
                port,
                is_reachable: false,
                latency_ms: None,
                error: Some("Connection timed out".to_string()),
            },
        }
    }

    pub fn ping_host(target: &str, count: u32) -> Result<PingResult, std::io::Error> {
        let output = std::process::Command::new("ping")
            .arg("-c")
            .arg(count.to_string())
            .arg("-W")
            .arg("2")
            .arg(target)
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut min_lat = None;
        let mut avg_lat = None;
        let mut max_lat = None;
        let mut packet_loss = 100.0;
        let mut received = 0;

        for line in stdout.lines() {
            if line.contains("packets transmitted") {
                // e.g. "4 packets transmitted, 4 received, 0% packet loss, time 3004ms"
                let parts: Vec<&str> = line.split(',').collect();
                for part in parts {
                    let p = part.trim();
                    if p.contains("received") {
                        if let Some(num_str) = p.split_whitespace().next() {
                            received = num_str.parse::<u32>().unwrap_or(0);
                        }
                    } else if p.contains("packet loss") {
                        if let Some(num_str) = p.split('%').next() {
                            if let Some(pct) = num_str.split_whitespace().last() {
                                packet_loss = pct.parse::<f64>().unwrap_or(100.0);
                            }
                        }
                    }
                }
            } else if line.contains("rtt min/avg/max/mdev") || line.contains("round-trip min/avg/max/stddev") {
                // e.g. "rtt min/avg/max/mdev = 12.345/14.567/18.901/2.123 ms"
                if let Some(stats_part) = line.split('=').nth(1) {
                    let vals: Vec<&str> = stats_part.split_whitespace().next().unwrap_or("").split('/').collect();
                    if vals.len() >= 3 {
                        min_lat = vals[0].parse::<f64>().ok();
                        avg_lat = vals[1].parse::<f64>().ok();
                        max_lat = vals[2].parse::<f64>().ok();
                    }
                }
            }
        }

        Ok(PingResult {
            target: target.to_string(),
            transmitted: count,
            received,
            min_latency_ms: min_lat,
            avg_latency_ms: avg_lat,
            max_latency_ms: max_lat,
            packet_loss_percent: packet_loss,
        })
    }

    pub fn get_routing_table() -> Vec<RouteEntry> {
        let mut routes = Vec::new();
        if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 8 {
                    let iface = fields[0];
                    let dest_hex = fields[1];
                    let gw_hex = fields[2];
                    let flags = fields[3];
                    let mask_hex = fields[7];

                    let dest = Self::hex_to_ipv4(dest_hex).unwrap_or_else(|| "0.0.0.0".to_string());
                    let gw = Self::hex_to_ipv4(gw_hex).unwrap_or_else(|| "0.0.0.0".to_string());
                    let mask = Self::hex_to_ipv4(mask_hex).unwrap_or_else(|| "255.255.255.255".to_string());

                    routes.push(RouteEntry {
                        destination: dest,
                        gateway: gw,
                        genmask: mask,
                        flags: flags.to_string(),
                        interface: iface.to_string(),
                    });
                }
            }
        }
        routes
    }

    fn hex_to_ipv4(hex_str: &str) -> Option<String> {
        let num = u32::from_str_radix(hex_str, 16).ok()?;
        let octets = num.to_ne_bytes();
        Some(format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]))
    }
}
