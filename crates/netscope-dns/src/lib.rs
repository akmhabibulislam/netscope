use chrono::Utc;
use netscope_core::DnsRecord;
use std::fs;
use std::net::IpAddr;
use std::time::Instant;
use trust_dns_resolver::TokioAsyncResolver;

pub struct DnsInspector {
    resolver: TokioAsyncResolver,
}

impl DnsInspector {
    pub fn new() -> Result<Self, anyhow::Error> {
        let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
        Ok(Self { resolver })
    }

    pub fn get_system_resolvers() -> Vec<String> {
        let mut servers = Vec::new();

        // 1. Check /etc/resolv.conf
        if let Ok(content) = fs::read_to_string("/etc/resolv.conf") {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("nameserver") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() > 1 {
                        servers.push(parts[1].to_string());
                    }
                }
            }
        }

        // 2. Check systemd-resolved stub or status if available
        if servers.is_empty() {
            servers.push("127.0.0.53".to_string());
        }

        servers
    }

    pub async fn resolve(&self, domain: &str, record_type: &str) -> Result<DnsRecord, anyhow::Error> {
        let start = Instant::now();
        let mut answers = Vec::new();

        match record_type.to_uppercase().as_str() {
            "A" => {
                let response = self.resolver.ipv4_lookup(domain).await?;
                for ip in response.iter() {
                    answers.push(ip.to_string());
                }
            }
            "AAAA" => {
                let response = self.resolver.ipv6_lookup(domain).await?;
                for ip in response.iter() {
                    answers.push(ip.to_string());
                }
            }
            "MX" => {
                let response = self.resolver.mx_lookup(domain).await?;
                for mx in response.iter() {
                    answers.push(format!("{} (pref {})", mx.exchange(), mx.preference()));
                }
            }
            "TXT" => {
                let response = self.resolver.txt_lookup(domain).await?;
                for txt in response.iter() {
                    answers.push(txt.to_string());
                }
            }
            _ => {
                // Default to lookup_ip
                let response = self.resolver.lookup_ip(domain).await?;
                for ip in response.iter() {
                    answers.push(ip.to_string());
                }
            }
        }

        let duration = start.elapsed().as_millis() as u64;
        let system_resolvers = Self::get_system_resolvers();
        let resolver_addr = system_resolvers.first().cloned().unwrap_or_else(|| "System Default".to_string());

        Ok(DnsRecord {
            id: format!("{}-{}-{}", Utc::now().timestamp_micros(), domain, record_type),
            timestamp: Utc::now(),
            query: domain.to_string(),
            qtype: record_type.to_uppercase(),
            response: Some(answers.join(", ")),
            resolver: resolver_addr,
            duration_ms: Some(duration),
            process_name: None,
        })
    }

    pub async fn reverse_lookup(&self, ip: IpAddr) -> Option<String> {
        if let Ok(lookup) = self.resolver.reverse_lookup(ip).await {
            lookup.iter().next().map(|name| name.to_utf8())
        } else {
            None
        }
    }
}
