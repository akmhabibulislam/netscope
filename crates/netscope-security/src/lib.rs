pub mod threat_intel;

use chrono::Utc;
use netscope_core::{AlertSeverity, BandwidthSample, ConnectionState, NetworkConnection, SecurityAlert};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
pub use threat_intel::ThreatIntel;

pub struct SecurityRuleEngine {
    whitelisted_ips: HashSet<String>,
    whitelisted_processes: HashSet<String>,
    seen_processes: HashSet<String>,
    process_connection_counts: HashMap<String, usize>,
    last_bandwidth_rx_speed: f64,
    threat_intel: ThreatIntel,
}

impl SecurityRuleEngine {
    pub fn new(whitelisted_ips: Vec<String>, whitelisted_processes: Vec<String>) -> Self {
        Self {
            whitelisted_ips: whitelisted_ips.into_iter().collect(),
            whitelisted_processes: whitelisted_processes.into_iter().collect(),
            seen_processes: HashSet::new(),
            process_connection_counts: HashMap::new(),
            last_bandwidth_rx_speed: 0.0,
            threat_intel: ThreatIntel::new(),
        }
    }

    pub fn evaluate_connections(&mut self, connections: &[NetworkConnection]) -> Vec<SecurityAlert> {
        let mut alerts = Vec::new();
        let now = Utc::now();

        // 1. Reset per-turn counters
        self.process_connection_counts.clear();

        for conn in connections {
            let proc_name = conn.process.as_ref().map(|p| p.name.clone()).unwrap_or_else(|| "Unknown".to_string());
            let remote_ip_str = conn.remote_addr.to_string();

            // Track connections per process
            *self.process_connection_counts.entry(proc_name.clone()).or_insert(0) += 1;

            // Whitelist skip
            if self.whitelisted_ips.contains(&remote_ip_str) || self.whitelisted_processes.contains(&proc_name) {
                continue;
            }

            // Rule 0: Offline Threat Intelligence (IoC match)
            if let Some(matched) = self.threat_intel.check_ip(conn.remote_addr) {
                alerts.push(SecurityAlert {
                    id: format!("ALERT-THREAT-{}", conn.id),
                    timestamp: now,
                    severity: AlertSeverity::Critical,
                    title: format!("Known Threat Detected: {}", matched.threat_type),
                    message: format!("Process '{}' connected to {}: {}. (Source: {})", proc_name, matched.ip, matched.description, matched.source),
                    rule_id: "RULE_THREAT_INTEL".to_string(),
                    affected_process: Some(proc_name.clone()),
                    remote_ip: Some(conn.remote_addr),
                    remote_port: Some(conn.remote_port),
                    recommendations: vec![
                        "Terminate connection immediately using NetScope Firewall".to_string(),
                        "Quarantine affected binary".to_string(),
                        "Scan host filesystem".to_string(),
                    ],
                    reviewed: false,
                });
            }

            // Rule 1: Unexpected Listening Ports on public interfaces (0.0.0.0 or ::)
            if conn.state == ConnectionState::Listen && (conn.local_addr.is_unspecified() || !conn.local_addr.is_loopback()) {
                // High risk ports (e.g. 22 SSH, 23 Telnet, 4444 Metasploit, 8080/8888, 3389 RDP, 5900 VNC)
                let suspicious_ports = [23, 4444, 5555, 6667, 31337];
                if suspicious_ports.contains(&conn.local_port) {
                    alerts.push(SecurityAlert {
                        id: format!("ALERT-LISTEN-{}", conn.id),
                        timestamp: now,
                        severity: AlertSeverity::High,
                        title: format!("Suspicious Listening Port Detected (: {})", conn.local_port),
                        message: format!("Process '{}' opened a listening socket on port {}. This port is frequently associated with reverse shells or remote administration tools.", proc_name, conn.local_port),
                        rule_id: "RULE_SUSPICIOUS_PORT".to_string(),
                        affected_process: Some(proc_name.clone()),
                        remote_ip: None,
                        remote_port: Some(conn.local_port),
                        recommendations: vec![
                            "Inspect the listening process using PID/executable path".to_string(),
                            "Verify if this service was intentionally started".to_string(),
                            "Consider closing the port or configuring a local firewall".to_string(),
                        ],
                        reviewed: false,
                    });
                }
            }

            // Rule 2: Connection to Reserved / Special IP Ranges
            if let IpAddr::V4(v4) = conn.remote_addr {
                if !v4.is_unspecified() && !v4.is_loopback() && !v4.is_private() {
                    // Check for documentation / test addresses or loopback spoofing
                    let octets = v4.octets();
                    if octets[0] == 0 || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2) {
                        alerts.push(SecurityAlert {
                            id: format!("ALERT-RESERVED-{}", conn.id),
                            timestamp: now,
                            severity: AlertSeverity::Medium,
                            title: format!("Connection to Reserved IP Space ({})", v4),
                            message: format!("Process '{}' is attempting communication with a reserved or test net address.", proc_name),
                            rule_id: "RULE_RESERVED_IP".to_string(),
                            affected_process: Some(proc_name.clone()),
                            remote_ip: Some(conn.remote_addr),
                            remote_port: Some(conn.remote_port),
                            recommendations: vec![
                                "Review application logs for misconfigured routing or test mocks".to_string(),
                            ],
                            reviewed: false,
                        });
                    }
                }
            }

            // Rule 3: Newly observed network process
            if !self.seen_processes.is_empty() && !self.seen_processes.contains(&proc_name) && proc_name != "Unknown" {
                alerts.push(SecurityAlert {
                    id: format!("ALERT-NEWPROC-{}-{}", proc_name, now.timestamp()),
                    timestamp: now,
                    severity: AlertSeverity::Info,
                    title: format!("New Network Active Process: {}", proc_name),
                    message: format!("Process '{}' (PID {}) was observed engaging in network communication for the first time in this session.", proc_name, conn.process.as_ref().map(|p| p.pid).unwrap_or(0)),
                    rule_id: "RULE_NEW_PROCESS".to_string(),
                    affected_process: Some(proc_name.clone()),
                    remote_ip: Some(conn.remote_addr),
                    remote_port: Some(conn.remote_port),
                    recommendations: vec![
                        "Verify that this is a recognized application".to_string(),
                        "Add to whitelist if this is a known trusted service".to_string(),
                    ],
                    reviewed: false,
                });
            }

            if proc_name != "Unknown" {
                self.seen_processes.insert(proc_name);
            }
        }

        // Rule 4: Process opening unusually high number of connections (> 50)
        for (proc, count) in &self.process_connection_counts {
            if *count > 60 && !self.whitelisted_processes.contains(proc) && proc != "Unknown" {
                alerts.push(SecurityAlert {
                    id: format!("ALERT-HIGHSOCK-{}-{}", proc, now.timestamp()),
                    timestamp: now,
                    severity: AlertSeverity::Medium,
                    title: format!("High Connection Count for {}", proc),
                    message: format!("Process '{}' has {} active network sockets open simultaneously.", proc, count),
                    rule_id: "RULE_HIGH_SOCKETS".to_string(),
                    affected_process: Some(proc.clone()),
                    remote_ip: None,
                    remote_port: None,
                    recommendations: vec![
                        "Check if this process is a P2P client, browser, or scanning tool".to_string(),
                        "Examine open socket states in the Connections tab".to_string(),
                    ],
                    reviewed: false,
                });
            }
        }

        alerts
    }

    pub fn evaluate_bandwidth(&mut self, sample: &BandwidthSample) -> Option<SecurityAlert> {
        let now = Utc::now();
        // Detect massive outbound traffic burst (> 150 Mbps)
        let tx_mbps = sample.tx_speed_bps / 1_000_000.0;
        let rx_mbps = sample.rx_speed_bps / 1_000_000.0;
        self.last_bandwidth_rx_speed = rx_mbps;

        if tx_mbps > 200.0 {
            return Some(SecurityAlert {
                id: format!("ALERT-BURST-TX-{}", now.timestamp()),
                timestamp: now,
                severity: AlertSeverity::High,
                title: "Massive Outbound Bandwidth Spike".to_string(),
                message: format!("Detected sustained outbound transfer rate of {:.2} Mbps, which may indicate unexpected data exfiltration or high-volume upload.", tx_mbps),
                rule_id: "RULE_BANDWIDTH_BURST".to_string(),
                affected_process: None,
                remote_ip: None,
                remote_port: None,
                recommendations: vec![
                    "Review top active processes in the Processes tab".to_string(),
                    "Check cloud backups or file synchronization tools".to_string(),
                ],
                reviewed: false,
            });
        }
        None
    }
}
