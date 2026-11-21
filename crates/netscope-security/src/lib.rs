pub mod pipeline;
pub mod threat_intel;

use chrono::Utc;
use netscope_core::{
    AlertSeverity, BandwidthSample, ConnectionState, NetworkConnection, SecurityAlert,
};
pub use pipeline::{FeedProvider, ThreatIndicator, ThreatPipeline};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;
pub use threat_intel::{
    DomainThreatEntry, DomainThreatMatch, ThreatEntry, ThreatIntel, ThreatMatch,
};

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

    pub fn evaluate_connections(
        &mut self,
        connections: &[NetworkConnection],
    ) -> Vec<SecurityAlert> {
        let mut alerts = Vec::new();
        let now = Utc::now();

        // 1. Reset per-turn counters
        self.process_connection_counts.clear();

        for conn in connections {
            let proc_name = conn
                .process
                .as_ref()
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "Unknown".to_string());
            let remote_ip_str = conn.remote_addr.to_string();

            // Track connections per process
            *self
                .process_connection_counts
                .entry(proc_name.clone())
                .or_insert(0) += 1;

            // Whitelist skip
            if self.whitelisted_ips.contains(&remote_ip_str)
                || self.whitelisted_processes.contains(&proc_name)
            {
                continue;
            }

            // Rule 0: Offline Threat Intelligence (IoC match)
            if let Some(matched) = self.threat_intel.check_ip(conn.remote_addr) {
                let is_tor = matched.threat_type.contains("Tor")
                    || matched.threat_type.contains("Anonymization");
                let severity = if is_tor {
                    AlertSeverity::Medium
                } else {
                    AlertSeverity::Critical
                };

                let title = if is_tor {
                    format!("Anonymizer / Privacy Relay: {}", matched.threat_type)
                } else {
                    format!("Known Threat Detected: {}", matched.threat_type)
                };

                let recs = if is_tor {
                    vec![
                        "Investigate if connection to privacy relay was intentional".to_string(),
                        "Verify application proxy or VPN configuration".to_string(),
                    ]
                } else {
                    vec![
                        "Terminate connection immediately using NetScope Firewall".to_string(),
                        "Quarantine affected binary".to_string(),
                        "Scan host filesystem".to_string(),
                    ]
                };

                alerts.push(SecurityAlert {
                    id: format!("ALERT-THREAT-{}", conn.id),
                    timestamp: now,
                    severity,
                    title,
                    message: format!(
                        "Process '{}' connected to {}: {}. (Source: {})",
                        proc_name, matched.ip, matched.description, matched.source
                    ),
                    rule_id: "RULE_THREAT_INTEL".to_string(),
                    affected_process: Some(proc_name.clone()),
                    remote_ip: Some(conn.remote_addr),
                    remote_port: Some(conn.remote_port),
                    recommendations: recs,
                    reviewed: false,
                });
            }

            // Rule 1: Unexpected Listening Ports on public interfaces (0.0.0.0 or ::)
            if conn.state == ConnectionState::Listen
                && (conn.local_addr.is_unspecified() || !conn.local_addr.is_loopback())
            {
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
            if !self.seen_processes.is_empty()
                && !self.seen_processes.contains(&proc_name)
                && proc_name != "Unknown"
            {
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
                    message: format!(
                        "Process '{}' has {} active network sockets open simultaneously.",
                        proc, count
                    ),
                    rule_id: "RULE_HIGH_SOCKETS".to_string(),
                    affected_process: Some(proc.clone()),
                    remote_ip: None,
                    remote_port: None,
                    recommendations: vec![
                        "Check if this process is a P2P client, browser, or scanning tool"
                            .to_string(),
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

    pub fn threat_intel(&self) -> &ThreatIntel {
        &self.threat_intel
    }

    pub fn threat_intel_mut(&mut self) -> &mut ThreatIntel {
        &mut self.threat_intel
    }

    pub fn ingest_indicators(&mut self, indicators: Vec<ThreatIndicator>) -> Result<usize, String> {
        let mut count = 0;
        for ind in indicators {
            if ind.indicator_type.eq_ignore_ascii_case("Domain")
                || (!ind.indicator.contains(':')
                    && ind.indicator.contains('.')
                    && std::net::IpAddr::from_str(&ind.indicator).is_err())
            {
                if let Some(norm) = ThreatIntel::normalize_domain(&ind.indicator) {
                    self.threat_intel.add_domain_ioc(DomainThreatEntry {
                        domain: norm,
                        category: ind.category,
                        description: format!("Automated feed ingestion from {}", ind.source),
                        source: ind.source,
                        confidence: ind.confidence,
                        first_seen: ind.first_seen,
                        expires_at: ind.expires_at,
                    });
                    count += 1;
                }
            } else if let Ok(ip) = std::str::FromStr::from_str(&ind.indicator) {
                self.threat_intel.add_ioc(ThreatEntry {
                    ip,
                    category: ind.category,
                    description: format!("Automated feed ingestion from {}", ind.source),
                    source: ind.source,
                    confidence: ind.confidence,
                    first_seen: ind.first_seen,
                    expires_at: ind.expires_at,
                });
                count += 1;
            }
        }
        self.threat_intel.save_to_disk()?;
        Ok(count)
    }

    /// Evaluates a DNS record against threat intelligence domains and answers
    pub fn evaluate_dns(&mut self, record: &netscope_core::DnsRecord) -> Option<SecurityAlert> {
        let now = Utc::now();

        // 1. Check queried domain
        if let Some(matched) = self.threat_intel.check_domain(&record.query) {
            return Some(SecurityAlert {
                id: format!("ALERT-DNS-DOMAIN-{}", now.timestamp_millis()),
                timestamp: now,
                severity: AlertSeverity::High,
                title: format!("Malicious Domain Query: {}", matched.domain),
                message: format!(
                    "DNS query for '{}' matched threat intelligence signature: {} (Source: {}).",
                    matched.domain, matched.threat_type, matched.source
                ),
                rule_id: "RULE_THREAT_DOMAIN".to_string(),
                affected_process: record.process_name.clone(),
                remote_ip: None,
                remote_port: Some(53),
                recommendations: vec![
                    "Inspect originating process or browser tab".to_string(),
                    "Block domain resolution using local DNS policy or /etc/hosts".to_string(),
                ],
                reviewed: false,
            });
        }

        // 2. Check resolved IP in response if available
        if let Some(ref resp) = record.response {
            for part in resp.split(',') {
                let trimmed = part.trim();
                if let Ok(ip) = std::net::IpAddr::from_str(trimmed) {
                    if let Some(matched) = self.threat_intel.check_ip(ip) {
                        let is_tor = matched.threat_type.contains("Tor")
                            || matched.threat_type.contains("Anonymization");
                        return Some(SecurityAlert {
                            id: format!("ALERT-DNS-IP-{}", now.timestamp_millis()),
                            timestamp: now,
                            severity: if is_tor {
                                AlertSeverity::Medium
                            } else {
                                AlertSeverity::Critical
                            },
                            title: if is_tor {
                                format!("DNS Resolved to Privacy Relay: {}", matched.threat_type)
                            } else {
                                format!("DNS Resolved to Malicious Host: {}", matched.threat_type)
                            },
                            message: format!(
                                "DNS query '{}' resolved to known indicator {}: {} (Source: {}).",
                                record.query, ip, matched.description, matched.source
                            ),
                            rule_id: "RULE_THREAT_DNS_IP".to_string(),
                            affected_process: record.process_name.clone(),
                            remote_ip: Some(ip),
                            remote_port: Some(53),
                            recommendations: vec![
                                "Review network traffic destined to this resolved IP address"
                                    .to_string(),
                            ],
                            reviewed: false,
                        });
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscope_core::DnsRecord;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ingest_indicators_all_three_types() {
        let mut engine = SecurityRuleEngine::new(vec![], vec![]);
        let now = Utc::now();
        let indicators = vec![
            ThreatIndicator {
                indicator: "194.26.29.115".to_string(),
                indicator_type: "IPv4".to_string(),
                category: "Malware C2".to_string(),
                source: "Test".to_string(),
                confidence: 95,
                first_seen: now,
                last_seen: now,
                expires_at: Some(now + chrono::Duration::days(10)),
            },
            ThreatIndicator {
                indicator: "2001:4860:4860::8888".to_string(),
                indicator_type: "IPv6".to_string(),
                category: "Botnet Node".to_string(),
                source: "Test".to_string(),
                confidence: 90,
                first_seen: now,
                last_seen: now,
                expires_at: Some(now + chrono::Duration::days(10)),
            },
            ThreatIndicator {
                indicator: "c2.bad-actor-domain.com".to_string(),
                indicator_type: "Domain".to_string(),
                category: "Malicious Payload Host".to_string(),
                source: "URLhaus".to_string(),
                confidence: 99,
                first_seen: now,
                last_seen: now,
                expires_at: Some(now + chrono::Duration::days(10)),
            },
        ];

        let count = engine
            .ingest_indicators(indicators)
            .expect("Must ingest successfully");
        assert_eq!(count, 3);

        // Verify IP check matches
        let ip_match = engine
            .threat_intel()
            .check_ip(IpAddr::V4(Ipv4Addr::new(194, 26, 29, 115)));
        assert!(ip_match.is_some());

        // Verify Domain check matches
        let dom_match = engine
            .threat_intel()
            .check_domain("c2.bad-actor-domain.com");
        assert!(dom_match.is_some());
        assert_eq!(dom_match.unwrap().confidence, 99);
    }

    #[test]
    fn test_evaluate_dns_with_malicious_domain_and_ip() {
        let mut engine = SecurityRuleEngine::new(vec![], vec![]);
        let now = Utc::now();

        engine.threat_intel_mut().add_domain_ioc(DomainThreatEntry {
            domain: "phishing-bank.net".to_string(),
            category: "Credential Harvester".to_string(),
            description: "Fake banking portal".to_string(),
            source: "PhishTank".to_string(),
            confidence: 95,
            first_seen: now,
            expires_at: Some(now + chrono::Duration::days(5)),
        });

        let record = DnsRecord {
            id: "dns-1".to_string(),
            timestamp: now,
            query: "phishing-bank.net".to_string(),
            qtype: "A".to_string(),
            response: Some("93.184.216.34".to_string()),
            duration_ms: Some(15),
            resolver: "1.1.1.1".to_string(),
            process_name: Some("curl".to_string()),
        };

        let alert = engine
            .evaluate_dns(&record)
            .expect("Must generate alert for phishing domain");
        assert_eq!(alert.rule_id, "RULE_THREAT_DOMAIN");
        assert_eq!(alert.severity, AlertSeverity::High);
        assert!(alert.title.contains("phishing-bank.net"));
    }

    #[test]
    fn test_tor_exit_node_never_classified_as_malware() {
        let mut engine = SecurityRuleEngine::new(vec![], vec![]);
        let tor_ip = IpAddr::V4(Ipv4Addr::new(185, 220, 101, 5));
        let m = engine
            .threat_intel()
            .check_ip(tor_ip)
            .expect("Must match baseline Tor exit");
        assert_eq!(m.threat_type, "Tor Anonymization Relay");

        let now = Utc::now();
        let conn = NetworkConnection {
            id: "conn-tor".to_string(),
            protocol: netscope_core::Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            local_port: 48210,
            remote_addr: tor_ip,
            remote_port: 443,
            state: netscope_core::ConnectionState::Established,
            inode: 12345,
            process: None,
            reverse_dns: None,
            country: None,
            city: None,
            asn: None,
            first_seen: now,
            last_seen: now,
        };

        let alerts = engine.evaluate_connections(&[conn]);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, AlertSeverity::Medium);
        assert!(!alerts[0].title.contains("Malware"));
        assert!(alerts[0].title.contains("Anonymizer / Privacy Relay"));
    }
}
