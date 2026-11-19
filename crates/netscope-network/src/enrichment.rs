use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpEnrichment {
    pub ip: String,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub org: Option<String>,
    pub asn: Option<String>,
}

pub struct EnrichmentService {
    client: reqwest::Client,
    cache: Arc<RwLock<HashMap<IpAddr, IpEnrichment>>>,
    enabled: bool,
}

impl EnrichmentService {
    pub fn new(enabled: bool) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(4))
                .build()
                .unwrap_or_default(),
            cache: Arc::new(RwLock::new(HashMap::new())),
            enabled,
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub async fn lookup_ip(&self, ip: IpAddr) -> Option<IpEnrichment> {
        if !self.enabled || ip.is_loopback() || ip.is_unspecified() {
            return None;
        }

        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(res) = cache.get(&ip) {
                return Some(res.clone());
            }
        }

        // Check if private IP
        if match ip {
            IpAddr::V4(v4) => v4.is_private(),
            IpAddr::V6(_) => false,
        } {
            return None;
        }

        // Query ip-api.com (free, rate limited to 45 req/min, non-commercial)
        let url = format!("http://ip-api.com/json/{}?fields=status,message,country,regionName,city,isp,org,as", ip);
        match self.client.get(&url).send().await {
            Ok(resp) => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if json.get("status").and_then(|s| s.as_str()) == Some("success") {
                        let enrichment = IpEnrichment {
                            ip: ip.to_string(),
                            country: json.get("country").and_then(|s| s.as_str()).map(|s| s.to_string()),
                            region: json.get("regionName").and_then(|s| s.as_str()).map(|s| s.to_string()),
                            city: json.get("city").and_then(|s| s.as_str()).map(|s| s.to_string()),
                            isp: json.get("isp").and_then(|s| s.as_str()).map(|s| s.to_string()),
                            org: json.get("org").and_then(|s| s.as_str()).map(|s| s.to_string()),
                            asn: json.get("as").and_then(|s| s.as_str()).map(|s| s.to_string()),
                        };
                        let mut cache = self.cache.write().await;
                        cache.insert(ip, enrichment.clone());
                        return Some(enrichment);
                    }
                }
            }
            Err(e) => {
                warn!("Enrichment lookup failed for {}: {}", ip, e);
            }
        }

        None
    }

    pub async fn lookup_public_ip(&self) -> Option<String> {
        if !self.enabled {
            return None;
        }

        let providers = [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://icanhazip.com",
        ];

        for url in providers {
            if let Ok(resp) = self.client.get(url).send().await {
                if let Ok(text) = resp.text().await {
                    let ip = text.trim();
                    if !ip.is_empty() {
                        return Some(ip.to_string());
                    }
                }
            }
        }
        None
    }
}
