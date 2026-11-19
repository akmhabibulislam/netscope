use serde::{Deserialize, Serialize};
use std::fs;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiInfo {
    pub interface: String,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub signal_dbm: Option<i32>,
    pub link_quality: Option<String>,
    pub frequency_ghz: Option<f64>,
    pub tx_bitrate_mbps: Option<f64>,
}

pub struct WifiScanner;

impl WifiScanner {
    pub fn get_wifi_details(iface_name: &str) -> Option<WifiInfo> {
        // Query iw dev <iface> link
        let output = Command::new("iw").args(["dev", iface_name, "link"]).output().ok()?;
        if !output.status.success() {
            // Fallback: check /proc/net/wireless
            return Self::fallback_proc_net_wireless(iface_name);
        }

        let text = String::from_utf8_lossy(&output.stdout);
        if text.contains("Not connected") {
            return None;
        }

        let mut ssid = None;
        let mut bssid = None;
        let mut signal_dbm = None;
        let mut freq = None;
        let mut bitrate = None;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Connected to") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 3 {
                    bssid = Some(parts[2].to_string());
                }
            } else if trimmed.starts_with("SSID:") {
                ssid = Some(trimmed[5..].trim().to_string());
            } else if trimmed.starts_with("freq:") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(mhz) = parts[1].parse::<f64>() {
                        freq = Some(mhz / 1000.0);
                    }
                }
            } else if trimmed.starts_with("signal:") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    signal_dbm = parts[1].parse::<i32>().ok();
                }
            } else if trimmed.starts_with("tx bitrate:") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 3 {
                    bitrate = parts[2].parse::<f64>().ok();
                }
            }
        }

        let link_quality = signal_dbm.map(|sig| {
            if sig >= -50 {
                "Excellent (100%)"
            } else if sig >= -60 {
                "Good (80%)"
            } else if sig >= -70 {
                "Fair (60%)"
            } else if sig >= -80 {
                "Weak (40%)"
            } else {
                "Very Poor (<20%)"
            }
            .to_string()
        });

        Some(WifiInfo {
            interface: iface_name.to_string(),
            ssid,
            bssid,
            signal_dbm,
            link_quality,
            frequency_ghz: freq,
            tx_bitrate_mbps: bitrate,
        })
    }

    fn fallback_proc_net_wireless(iface_name: &str) -> Option<WifiInfo> {
        let content = fs::read_to_string("/proc/net/wireless").ok()?;
        for line in content.lines().skip(2) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 && parts[0].trim_end_matches(':') == iface_name {
                let quality_val = parts[2].trim_end_matches('.').parse::<i32>().unwrap_or(0);
                return Some(WifiInfo {
                    interface: iface_name.to_string(),
                    ssid: Some("Connected Wi-Fi".to_string()),
                    bssid: None,
                    signal_dbm: Some(quality_val - 100),
                    link_quality: Some(format!("{}%", quality_val)),
                    frequency_ghz: None,
                    tx_bitrate_mbps: None,
                });
            }
        }
        None
    }
}
