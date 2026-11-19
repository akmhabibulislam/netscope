use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatMatch {
    pub ip: IpAddr,
    pub threat_type: String,
    pub description: String,
    pub source: String,
}

pub struct ThreatIntel {
    known_malicious_ips: HashSet<IpAddr>,
    tor_exit_nodes: HashSet<IpAddr>,
}

impl ThreatIntel {
    pub fn new() -> Self {
        let mut known_malicious_ips = HashSet::new();
        let mut tor_exit_nodes = HashSet::new();

        // Populate offline threat database with known sample C2s and test IoCs
        // (Real deployments can auto-refresh this file locally into ~/.local/share/netscope/threats.db)
        if let Ok(ip) = "198.51.100.23".parse() {
            known_malicious_ips.insert(ip);
        }
        if let Ok(ip) = "203.0.113.88".parse() {
            known_malicious_ips.insert(ip);
        }
        if let Ok(ip) = "185.220.101.5".parse() {
            tor_exit_nodes.insert(ip);
        }

        Self {
            known_malicious_ips,
            tor_exit_nodes,
        }
    }

    pub fn check_ip(&self, ip: IpAddr) -> Option<ThreatMatch> {
        if self.known_malicious_ips.contains(&ip) {
            return Some(ThreatMatch {
                ip,
                threat_type: "Known Malware / C2 Node".to_string(),
                description: "This remote address matches an active command-and-control server signature.".to_string(),
                source: "Offline Threat Feed".to_string(),
            });
        }

        if self.tor_exit_nodes.contains(&ip) {
            return Some(ThreatMatch {
                ip,
                threat_type: "Tor Exit Relay".to_string(),
                description: "Traffic is being routed through a verified public Tor exit node.".to_string(),
                source: "Tor Project Directory".to_string(),
            });
        }

        None
    }
}

impl Default for ThreatIntel {
    fn default() -> Self {
        Self::new()
    }
}
