use netscope_core::{InterfaceStats, InterfaceType, NetworkInterface, OperState};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

pub struct InterfaceManager {
    last_stats: HashMap<String, (InterfaceStats, std::time::Instant)>,
}

impl InterfaceManager {
    pub fn new() -> Self {
        Self {
            last_stats: HashMap::new(),
        }
    }

    pub fn discover_interfaces(&mut self) -> Vec<NetworkInterface> {
        let net_dir = Path::new("/sys/class/net");
        if !net_dir.exists() {
            return Vec::new();
        }

        let mut interfaces = Vec::new();
        let default_iface = self.find_default_interface();

        if let Ok(entries) = fs::read_dir(net_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let if_path = entry.path();

                let is_loopback = name == "lo";
                let oper_state = self.read_oper_state(&if_path);
                let is_up = oper_state == OperState::Up;
                let mtu = self.read_u32(&if_path.join("mtu")).unwrap_or(1500);
                let if_index = self.read_u32(&if_path.join("ifindex")).unwrap_or(0);
                let mac_address = self.read_mac(&if_path.join("address"));
                let if_type = self.determine_interface_type(&name, &if_path);

                let stats = self.read_stats(&if_path.join("statistics"));
                let (rx_speed, tx_speed) = self.calculate_speeds(&name, &stats);

                let (ipv4_addresses, ipv6_addresses) = self.read_addresses(&name);
                let is_default = default_iface.as_deref() == Some(&name);

                interfaces.push(NetworkInterface {
                    name,
                    if_index,
                    if_type,
                    oper_state,
                    mac_address,
                    ipv4_addresses,
                    ipv6_addresses,
                    mtu,
                    is_up,
                    is_loopback,
                    is_default,
                    stats,
                    rx_speed_bps: rx_speed,
                    tx_speed_bps: tx_speed,
                });
            }
        }

        interfaces.sort_by(|a, b| {
            if a.is_default {
                std::cmp::Ordering::Less
            } else if b.is_default {
                std::cmp::Ordering::Greater
            } else {
                a.name.cmp(&b.name)
            }
        });

        interfaces
    }

    fn read_oper_state(&self, path: &Path) -> OperState {
        if let Ok(content) = fs::read_to_string(path.join("operstate")) {
            match content.trim() {
                "up" => OperState::Up,
                "down" => OperState::Down,
                _ => OperState::Unknown,
            }
        } else {
            OperState::Unknown
        }
    }

    fn read_u32(&self, path: &Path) -> Option<u32> {
        fs::read_to_string(path).ok().and_then(|s| s.trim().parse().ok())
    }

    fn read_mac(&self, path: &Path) -> Option<String> {
        fs::read_to_string(path).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty() && s != "00:00:00:00:00:00")
    }

    fn determine_interface_type(&self, name: &str, path: &Path) -> InterfaceType {
        if name == "lo" {
            return InterfaceType::Loopback;
        }
        if name.starts_with("wl") || name.starts_with("wlan") {
            return InterfaceType::WiFi;
        }
        if name.starts_with("en") || name.starts_with("eth") {
            return InterfaceType::Ethernet;
        }
        if name.starts_with("br") {
            return InterfaceType::Bridge;
        }
        if name.starts_with("tun") || name.starts_with("tap") || name.starts_with("wg") {
            return InterfaceType::Vpn;
        }
        if name.starts_with("veth") || name.starts_with("docker") || name.starts_with("virbr") {
            return InterfaceType::Virtual;
        }
        if path.join("wireless").exists() || path.join("phy80211").exists() {
            return InterfaceType::WiFi;
        }

        InterfaceType::Unknown(name.to_string())
    }

    fn read_stats(&self, stats_path: &Path) -> InterfaceStats {
        let read_stat = |name: &str| -> u64 {
            fs::read_to_string(stats_path.join(name))
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(0)
        };

        InterfaceStats {
            rx_bytes: read_stat("rx_bytes"),
            tx_bytes: read_stat("tx_bytes"),
            rx_packets: read_stat("rx_packets"),
            tx_packets: read_stat("tx_packets"),
            rx_errors: read_stat("rx_errors"),
            tx_errors: read_stat("tx_errors"),
            rx_dropped: read_stat("rx_dropped"),
            tx_dropped: read_stat("tx_dropped"),
        }
    }

    fn calculate_speeds(&mut self, name: &str, current_stats: &InterfaceStats) -> (f64, f64) {
        let now = std::time::Instant::now();
        if let Some((prev_stats, prev_time)) = self.last_stats.insert(name.to_string(), (current_stats.clone(), now)) {
            let duration = now.duration_since(prev_time).as_secs_f64();
            if duration > 0.05 {
                let rx_diff = current_stats.rx_bytes.saturating_sub(prev_stats.rx_bytes);
                let tx_diff = current_stats.tx_bytes.saturating_sub(prev_stats.tx_bytes);

                let rx_bps = (rx_diff as f64 * 8.0) / duration;
                let tx_bps = (tx_diff as f64 * 8.0) / duration;
                return (rx_bps, tx_bps);
            }
        }
        (0.0, 0.0)
    }

    fn find_default_interface(&self) -> Option<String> {
        // Read /proc/net/route to find the default route (Destination 00000000)
        if let Ok(content) = fs::read_to_string("/proc/net/route") {
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 2 && fields[1] == "00000000" {
                    return Some(fields[0].to_string());
                }
            }
        }
        None
    }

    fn read_addresses(&self, if_name: &str) -> (Vec<String>, Vec<String>) {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();

        // Parse /proc/net/fib_trie or parse network addresses
        // Alternatively, use `ip -o addr` or /proc/net/if_inet6
        if let Ok(content) = fs::read_to_string("/proc/net/if_inet6") {
            for line in content.lines() {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 6 && fields[5] == if_name {
                    let hex_addr = fields[0];
                    if hex_addr.len() == 32 {
                        let mut segments = Vec::new();
                        for i in (0..32).step_by(4) {
                            segments.push(&hex_addr[i..i+4]);
                        }
                        let formatted = segments.join(":");
                        if let Ok(ip) = formatted.parse::<IpAddr>() {
                            v6.push(ip.to_string());
                        }
                    }
                }
            }
        }

        // Check if there are IPv4 addresses in /proc/net/arp or via simple shell command fallback
        // Or get from /sys if available. A lightweight fallback for IPv4 without external deps:
        if let Ok(out) = std::process::Command::new("ip").args(["-4", "-brief", "addr", "show", if_name]).output() {
            let s = String::from_utf8_lossy(&out.stdout);
            for part in s.split_whitespace() {
                if part.contains('/') && part.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    v4.push(part.to_string());
                }
            }
        }

        (v4, v6)
    }
}

impl Default for InterfaceManager {
    fn default() -> Self {
        Self::new()
    }
}
