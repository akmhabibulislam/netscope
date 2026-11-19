use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator: String,
    pub indicator_type: String, // "IPv4", "IPv6", "Domain"
    pub category: String,
    pub source: String,
    pub confidence: u8,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedProvider {
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub last_updated: Option<DateTime<Utc>>,
    pub total_indicators: usize,
}

pub struct ThreatPipeline {
    providers: Vec<FeedProvider>,
}

impl ThreatPipeline {
    pub fn new() -> Self {
        Self {
            providers: vec![
                FeedProvider {
                    id: "feodo".to_string(),
                    name: "Feodo Tracker Botnet C2 (abuse.ch)".to_string(),
                    url: "https://feodotracker.abuse.ch/downloads/ipblocklist.json".to_string(),
                    enabled: true,
                    last_updated: None,
                    total_indicators: 0,
                },
                FeedProvider {
                    id: "urlhaus".to_string(),
                    name: "URLhaus Malicious Payload Distribution".to_string(),
                    url: "https://urlhaus.abuse.ch/downloads/json_recent/".to_string(),
                    enabled: true,
                    last_updated: None,
                    total_indicators: 0,
                },
                FeedProvider {
                    id: "tor_exits".to_string(),
                    name: "Tor Project Public Consensus Directory".to_string(),
                    url: "https://check.torproject.org/torbulkexitlist".to_string(),
                    enabled: true,
                    last_updated: None,
                    total_indicators: 0,
                },
            ],
        }
    }

    pub fn providers(&self) -> &[FeedProvider] {
        &self.providers
    }

    /// Fetches, validates, and parses an update from a supported remote feed
    pub async fn fetch_feed_updates(&mut self, provider_id: &str) -> Result<Vec<ThreatIndicator>, String> {
        let provider = self.providers.iter_mut().find(|p| p.id == provider_id)
            .ok_or_else(|| format!("Unknown provider id: {}", provider_id))?;

        if !provider.enabled {
            return Err(format!("Provider {} is disabled", provider_id));
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(12))
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))?;

        let resp = client.get(&provider.url)
            .send()
            .await
            .map_err(|e| format!("Network request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Feed server returned HTTP {}", resp.status()));
        }

        // Bounded response size: max 5 MB to prevent memory exhaustion
        let content_length = resp.content_length().unwrap_or(0);
        if content_length > 5 * 1024 * 1024 {
            return Err("Feed response exceeded maximum allowed size (5MB)".to_string());
        }

        let body = resp.text().await.map_err(|e| format!("Failed to read body: {}", e))?;
        let now = Utc::now();
        let mut indicators = Vec::new();

        match provider_id {
            "tor_exits" => {
                for line in body.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    if let Ok(ip) = IpAddr::from_str(trimmed) {
                        indicators.push(ThreatIndicator {
                            indicator: ip.to_string(),
                            indicator_type: if ip.is_ipv4() { "IPv4".to_string() } else { "IPv6".to_string() },
                            category: "Tor Anonymization Relay".to_string(),
                            source: provider.name.clone(),
                            confidence: 85, // Transparent separate classification, not 95+ malware
                            first_seen: now,
                            last_seen: now,
                            expires_at: Some(now + chrono::Duration::days(14)),
                        });
                    }
                }
            }
            "feodo" => {
                // Feodo Tracker JSON format: array of objects with "ip_address", "malware", etc.
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(arr) = val.as_array() {
                        for item in arr {
                            if let Some(ip_str) = item.get("ip_address").and_then(|v| v.as_str()) {
                                if let Ok(ip) = IpAddr::from_str(ip_str) {
                                    let malware = item.get("malware").and_then(|v| v.as_str()).unwrap_or("Botnet C2");
                                    indicators.push(ThreatIndicator {
                                        indicator: ip.to_string(),
                                        indicator_type: if ip.is_ipv4() { "IPv4".to_string() } else { "IPv6".to_string() },
                                        category: format!("Malware C2 ({})", malware),
                                        source: provider.name.clone(),
                                        confidence: 95,
                                        first_seen: now,
                                        last_seen: now,
                                        expires_at: Some(now + chrono::Duration::days(30)),
                                    });
                                }
                            }
                        }
                    }
                }
            }
            "urlhaus" => {
                // URLhaus recent payload JSON
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(urls) = val.get("urls").and_then(|v| v.as_array()) {
                        for item in urls {
                            if let Some(host) = item.get("host").and_then(|v| v.as_str()) {
                                if let Ok(ip) = IpAddr::from_str(host) {
                                    indicators.push(ThreatIndicator {
                                        indicator: ip.to_string(),
                                        indicator_type: if ip.is_ipv4() { "IPv4".to_string() } else { "IPv6".to_string() },
                                        category: "Malicious Payload Host".to_string(),
                                        source: provider.name.clone(),
                                        confidence: 90,
                                        first_seen: now,
                                        last_seen: now,
                                        expires_at: Some(now + chrono::Duration::days(14)),
                                    });
                                }
                            }
                        }
                    }
                }
            }
            _ => return Err(format!("Parser not implemented for provider {}", provider_id)),
        }

        provider.last_updated = Some(now);
        provider.total_indicators = indicators.len();
        Ok(indicators)
    }
}

impl Default for ThreatPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tor_bulk_exit_list_fixture() {
        let fixture = "\
# Tor exit list
185.220.101.5
# Comment line
192.42.116.16
invalid-ip
2001:db8::1
";
        let mut count = 0;
        for line in fixture.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') && IpAddr::from_str(trimmed).is_ok() {
                count += 1;
            }
        }
        assert_eq!(count, 3);
    }

    #[test]
    fn test_parse_feodo_tracker_json_fixture() {
        let json = r#"[
            {"ip_address": "194.26.29.114", "malware": "Emotet", "status": "online"},
            {"ip_address": "45.154.255.88", "malware": "QakBot", "status": "offline"}
        ]"#;

        let val: serde_json::Value = serde_json::from_str(json).unwrap();
        let arr = val.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].get("ip_address").unwrap().as_str().unwrap(), "194.26.29.114");
    }
}
