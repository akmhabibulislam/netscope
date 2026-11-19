use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatMatch {
    pub ip: IpAddr,
    pub threat_type: String,
    pub description: String,
    pub source: String,
    pub confidence: u8,
    pub first_seen: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEntry {
    pub ip: IpAddr,
    pub category: String,
    pub description: String,
    pub source: String,
    pub confidence: u8,
    pub first_seen: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeedFile {
    pub version: u32,
    pub feed_name: String,
    pub last_updated: DateTime<Utc>,
    pub entries: Vec<ThreatEntry>,
}

pub struct ThreatIntel {
    /// Local threat intelligence repository with expiration tracking
    feed_entries: HashMap<IpAddr, ThreatEntry>,
    storage_path: PathBuf,
}

impl ThreatIntel {
    pub fn new() -> Self {
        let storage_path = directories::ProjectDirs::from("org", "netscope", "NetScope")
            .map(|dirs| dirs.data_dir().join("threat_feed.json"))
            .unwrap_or_else(|| PathBuf::from("threat_feed.json"));

        let mut intel = Self {
            feed_entries: HashMap::new(),
            storage_path,
        };

        // Attempt to load previously persisted threat feed if available on disk
        intel.load_from_disk();

        // If local feed is empty, populate verified baseline signatures
        if intel.feed_entries.is_empty() {
            intel.populate_baseline();
        }

        intel
    }

    fn populate_baseline(&mut self) {
        let now = Utc::now();
        let default_expiration = now + chrono::Duration::days(30);

        // Curated, verified exit nodes (Tor Project public consensus)
        let tor_exits = [
            ("185.220.101.5", "Tor Project Public Consensus"),
            ("185.220.101.6", "Tor Project Public Consensus"),
            ("185.220.101.7", "Tor Project Public Consensus"),
            ("192.42.116.16", "Tor Project Public Consensus"),
            ("198.98.51.189", "Tor Project Public Consensus"),
            ("171.25.193.20", "Tor Project Public Consensus"),
        ];

        for (ip_str, source) in tor_exits {
            if let Ok(ip) = IpAddr::from_str(ip_str) {
                self.feed_entries.insert(
                    ip,
                    ThreatEntry {
                        ip,
                        category: "Tor Anonymization Relay".to_string(),
                        description: "Public Tor exit node routing privacy-preserving or redirected traffic."
                            .to_string(),
                        source: source.to_string(),
                        confidence: 90,
                        first_seen: now,
                        expires_at: Some(default_expiration),
                    },
                );
            }
        }

        // Active Threat Probes (Documented CINS Army & AbuseIPDB high-frequency bot scanners)
        let malicious_scanners = [
            ("185.180.143.11", "CINS Army Threat Feed", "Automated mass port scanner & SSH probe"),
            ("45.154.255.88", "Feodo Tracker / AbuseIPDB", "Botnet C2 payload delivery probe"),
            ("194.26.29.114", "Spamhaus DROP / Shadowserver", "Brute-force credential scanner"),
            ("193.163.125.10", "AlienVault OTX", "Active exploit scanner and vulnerability probe"),
        ];

        for (ip_str, source, desc) in malicious_scanners {
            if let Ok(ip) = IpAddr::from_str(ip_str) {
                self.feed_entries.insert(
                    ip,
                    ThreatEntry {
                        ip,
                        category: "Malicious Recon / Scanner".to_string(),
                        description: desc.to_string(),
                        source: source.to_string(),
                        confidence: 92,
                        first_seen: now,
                        expires_at: Some(default_expiration),
                    },
                );
            }
        }
    }

    /// Load threat intelligence entries from local JSON feed file
    pub fn load_from_disk(&mut self) {
        if !self.storage_path.exists() {
            return;
        }

        if let Ok(content) = fs::read_to_string(&self.storage_path) {
            if let Ok(feed) = serde_json::from_str::<ThreatFeedFile>(&content) {
                info!("Loaded {} threat indicators from local cache: {:?}", feed.entries.len(), self.storage_path);
                for entry in feed.entries {
                    self.feed_entries.insert(entry.ip, entry);
                }
            }
        }
    }

    /// Persist current threat intelligence entries to disk
    pub fn save_to_disk(&self) -> Result<(), String> {
        if let Some(parent) = self.storage_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let feed = ThreatFeedFile {
            version: 1,
            feed_name: "NetScope Local Threat Database".to_string(),
            last_updated: Utc::now(),
            entries: self.feed_entries.values().cloned().collect(),
        };

        let json = serde_json::to_string_pretty(&feed)
            .map_err(|e| format!("Serialization error: {}", e))?;
        fs::write(&self.storage_path, json)
            .map_err(|e| format!("Disk write error: {}", e))?;
        Ok(())
    }

    /// Imports a threat intelligence feed from JSON file
    pub fn import_feed_file(&mut self, path: &Path) -> Result<usize, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Cannot read threat file: {}", e))?;
        let feed: ThreatFeedFile = serde_json::from_str(&content)
            .map_err(|e| format!("Invalid threat feed schema: {}", e))?;

        let count = feed.entries.len();
        for entry in feed.entries {
            self.feed_entries.insert(entry.ip, entry);
        }
        let _ = self.save_to_disk();
        Ok(count)
    }

    /// Check if a remote IP address matches any local threat intelligence signature
    /// Filters out expired entries and preserves non-malicious anonymization distinctions.
    pub fn check_ip(&self, ip: IpAddr) -> Option<ThreatMatch> {
        // Never flag loopback, private RFC1918, or documentation IPs
        if ip.is_loopback() || ip.is_unspecified() {
            return None;
        }

        match ip {
            IpAddr::V4(v4) => {
                if v4.is_private() || v4.is_documentation() {
                    return None;
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_unicast_link_local() {
                    return None;
                }
            }
        }

        if let Some(entry) = self.feed_entries.get(&ip) {
            // Check expiration
            if let Some(exp) = entry.expires_at {
                if exp < Utc::now() {
                    return None; // Indicator expired
                }
            }

            return Some(ThreatMatch {
                ip,
                threat_type: entry.category.clone(),
                description: entry.description.clone(),
                source: entry.source.clone(),
                confidence: entry.confidence,
                first_seen: entry.first_seen,
                expires_at: entry.expires_at,
            });
        }

        None
    }

    /// Add a verified indicator of compromise (IoC) with timestamp and expiry
    pub fn add_ioc(&mut self, entry: ThreatEntry) {
        self.feed_entries.insert(entry.ip, entry);
    }

    pub fn len(&self) -> usize {
        self.feed_entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.feed_entries.is_empty()
    }
}

impl Default for ThreatIntel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_documentation_ips_not_flagged() {
        let intel = ThreatIntel::new();
        assert!(intel.check_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))).is_none());
        assert!(intel.check_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23))).is_none());
    }

    #[test]
    fn test_expired_indicator_ignored() {
        let mut intel = ThreatIntel::new();
        let test_ip = IpAddr::V4(Ipv4Addr::new(45, 33, 32, 1));
        intel.add_ioc(ThreatEntry {
            ip: test_ip,
            category: "Expired Scanner".to_string(),
            description: "Old signature".to_string(),
            source: "Test Feed".to_string(),
            confidence: 90,
            first_seen: Utc::now() - chrono::Duration::days(40),
            expires_at: Some(Utc::now() - chrono::Duration::days(1)), // Expired yesterday
        });

        assert!(intel.check_ip(test_ip).is_none());
    }

    #[test]
    fn test_valid_indicator_matched() {
        let mut intel = ThreatIntel::new();
        let test_ip = IpAddr::V4(Ipv4Addr::new(45, 33, 32, 2));
        intel.add_ioc(ThreatEntry {
            ip: test_ip,
            category: "Active Botnet Probe".to_string(),
            description: "Verified active probe".to_string(),
            source: "Test Feed".to_string(),
            confidence: 95,
            first_seen: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::days(10)),
        });

        let m = intel.check_ip(test_ip).expect("Must match active indicator");
        assert_eq!(m.confidence, 95);
        assert_eq!(m.threat_type, "Active Botnet Probe");
    }
}
