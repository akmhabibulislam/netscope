use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

const MAX_FEED_SIZE_BYTES: usize = 5 * 1024 * 1024; // 5 MB bounded streaming limit

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
    pub async fn fetch_feed_updates(
        &mut self,
        provider_id: &str,
    ) -> Result<Vec<ThreatIndicator>, String> {
        let provider = self
            .providers
            .iter_mut()
            .find(|p| p.id == provider_id)
            .ok_or_else(|| format!("Unknown provider id: {}", provider_id))?;

        if !provider.enabled {
            return Err(format!("Provider {} is disabled", provider_id));
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(12))
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))?;

        let mut resp = client
            .get(&provider.url)
            .send()
            .await
            .map_err(|e| format!("Network request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Feed server returned HTTP {}", resp.status()));
        }

        // Bounded response streaming: enforces 5 MB limit even if Content-Length header is omitted
        let mut body_bytes = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| format!("Stream error reading feed: {}", e))?
        {
            if body_bytes.len() + chunk.len() > MAX_FEED_SIZE_BYTES {
                return Err(format!(
                    "Feed response exceeded maximum allowed size of 5MB (received {} bytes)",
                    body_bytes.len() + chunk.len()
                ));
            }
            body_bytes.extend_from_slice(&chunk);
        }

        let body = String::from_utf8(body_bytes)
            .map_err(|e| format!("Feed response is not valid UTF-8: {}", e))?;
        let now = Utc::now();

        let indicators = Self::parse_feed_body(provider_id, &provider.name, &body, now)?;

        if indicators.is_empty() {
            return Err(format!(
                "Feed '{}' returned zero valid threat indicators",
                provider_id
            ));
        }

        // Only update metadata on verified successful parse
        provider.last_updated = Some(now);
        provider.total_indicators = indicators.len();
        Ok(indicators)
    }

    /// Synchronous and deterministic parser for supported threat feed formats
    pub fn parse_feed_body(
        provider_id: &str,
        provider_name: &str,
        body: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<ThreatIndicator>, String> {
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
                            indicator_type: if ip.is_ipv4() {
                                "IPv4".to_string()
                            } else {
                                "IPv6".to_string()
                            },
                            category: "Tor Anonymization Relay".to_string(),
                            source: provider_name.to_string(),
                            confidence: 85,
                            first_seen: now,
                            last_seen: now,
                            expires_at: Some(now + chrono::Duration::days(14)),
                        });
                    }
                }
            }
            "feodo" => {
                let val: serde_json::Value = serde_json::from_str(body)
                    .map_err(|e| format!("Feodo Tracker feed invalid JSON: {}", e))?;

                let arr = val.as_array().ok_or_else(|| {
                    "Feodo Tracker JSON response root must be an array".to_string()
                })?;

                for item in arr {
                    if let Some(ip_str) = item.get("ip_address").and_then(|v| v.as_str()) {
                        if let Ok(ip) = IpAddr::from_str(ip_str.trim()) {
                            let malware = item
                                .get("malware")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Botnet C2");
                            indicators.push(ThreatIndicator {
                                indicator: ip.to_string(),
                                indicator_type: if ip.is_ipv4() {
                                    "IPv4".to_string()
                                } else {
                                    "IPv6".to_string()
                                },
                                category: format!("Malware C2 ({})", malware),
                                source: provider_name.to_string(),
                                confidence: 95,
                                first_seen: now,
                                last_seen: now,
                                expires_at: Some(now + chrono::Duration::days(30)),
                            });
                        }
                    }
                }
            }
            "urlhaus" => {
                let val: serde_json::Value = serde_json::from_str(body)
                    .map_err(|e| format!("URLhaus feed invalid JSON: {}", e))?;

                let urls = val
                    .get("urls")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| "URLhaus response missing 'urls' array schema".to_string())?;

                for item in urls {
                    if let Some(host) = item.get("host").and_then(|v| v.as_str()) {
                        let host_trimmed = host.trim();
                        if host_trimmed.is_empty() {
                            continue;
                        }
                        if let Ok(ip) = IpAddr::from_str(host_trimmed) {
                            indicators.push(ThreatIndicator {
                                indicator: ip.to_string(),
                                indicator_type: if ip.is_ipv4() {
                                    "IPv4".to_string()
                                } else {
                                    "IPv6".to_string()
                                },
                                category: "Malicious Payload Host".to_string(),
                                source: provider_name.to_string(),
                                confidence: 90,
                                first_seen: now,
                                last_seen: now,
                                expires_at: Some(now + chrono::Duration::days(14)),
                            });
                        } else if host_trimmed.contains('.') && !host_trimmed.contains(' ') {
                            // Valid domain indicator preserved accurately
                            indicators.push(ThreatIndicator {
                                indicator: host_trimmed.to_lowercase(),
                                indicator_type: "Domain".to_string(),
                                category: "Malicious Payload Distribution Domain".to_string(),
                                source: provider_name.to_string(),
                                confidence: 90,
                                first_seen: now,
                                last_seen: now,
                                expires_at: Some(now + chrono::Duration::days(14)),
                            });
                        }
                    }
                }
            }
            _ => {
                return Err(format!(
                    "Parser not implemented for provider {}",
                    provider_id
                ))
            }
        }

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
        let now = Utc::now();
        let indicators =
            ThreatPipeline::parse_feed_body("tor_exits", "Tor Project", fixture, now).unwrap();
        assert_eq!(indicators.len(), 3);
        assert_eq!(indicators[0].indicator, "185.220.101.5");
        assert_eq!(indicators[0].indicator_type, "IPv4");
        assert_eq!(indicators[2].indicator, "2001:db8::1");
        assert_eq!(indicators[2].indicator_type, "IPv6");
    }

    #[test]
    fn test_parse_feodo_tracker_json_fixture() {
        let json = r#"[
            {"ip_address": "194.26.29.114", "malware": "Emotet", "status": "online"},
            {"ip_address": "45.154.255.88", "malware": "QakBot", "status": "offline"}
        ]"#;

        let now = Utc::now();
        let indicators =
            ThreatPipeline::parse_feed_body("feodo", "Feodo Tracker", json, now).unwrap();
        assert_eq!(indicators.len(), 2);
        assert_eq!(indicators[0].indicator, "194.26.29.114");
        assert_eq!(indicators[0].category, "Malware C2 (Emotet)");
    }

    #[test]
    fn test_parse_urlhaus_json_with_both_ips_and_domains() {
        let json = r#"{
            "query_status": "ok",
            "urls": [
                {"host": "198.51.100.22", "threat": "malware_download"},
                {"host": "evil-c2-payload.example.com", "threat": "malware_download"},
                {"host": "", "threat": "empty"}
            ]
        }"#;

        let now = Utc::now();
        let indicators = ThreatPipeline::parse_feed_body("urlhaus", "URLhaus", json, now).unwrap();
        assert_eq!(indicators.len(), 2);
        assert_eq!(indicators[0].indicator, "198.51.100.22");
        assert_eq!(indicators[0].indicator_type, "IPv4");
        assert_eq!(indicators[1].indicator, "evil-c2-payload.example.com");
        assert_eq!(indicators[1].indicator_type, "Domain");
    }

    #[test]
    fn test_invalid_json_returns_real_error() {
        let invalid = "<html><title>500 Internal Server Error</title></html>";
        let now = Utc::now();
        assert!(ThreatPipeline::parse_feed_body("feodo", "Feodo", invalid, now).is_err());
        assert!(ThreatPipeline::parse_feed_body("urlhaus", "URLhaus", invalid, now).is_err());
    }
}
