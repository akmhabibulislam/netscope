use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

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

    /// Fetches and parses an update from a supported remote feed
    pub async fn fetch_feed_updates(&mut self, provider_id: &str) -> Result<Vec<ThreatIndicator>, String> {
        let provider = self.providers.iter_mut().find(|p| p.id == provider_id)
            .ok_or_else(|| format!("Unknown provider id: {}", provider_id))?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))?;

        let resp = client.get(&provider.url)
            .send()
            .await
            .map_err(|e| format!("Network request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Feed server returned HTTP {}", resp.status()));
        }

        let body = resp.text().await.map_err(|e| format!("Failed to read body: {}", e))?;
        let now = Utc::now();
        let mut indicators = Vec::new();

        if provider_id == "tor_exits" {
            for line in body.lines() {
                let trimmed = line.trim();
                if let Ok(ip) = trimmed.parse::<IpAddr>() {
                    indicators.push(ThreatIndicator {
                        indicator: ip.to_string(),
                        indicator_type: if ip.is_ipv4() { "IPv4".to_string() } else { "IPv6".to_string() },
                        category: "Tor Anonymization Relay".to_string(),
                        source: provider.name.clone(),
                        confidence: 90,
                        first_seen: now,
                        last_seen: now,
                        expires_at: Some(now + chrono::Duration::days(14)),
                    });
                }
            }
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
