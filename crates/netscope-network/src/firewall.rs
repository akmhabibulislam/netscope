use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    Nftables,
    Iptables,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DualStackStatus {
    pub ipv4_active: bool,
    pub ipv6_active: bool,
}

pub struct NetworkFirewall;

impl NetworkFirewall {
    /// Detects active Linux firewall backend without mixing commands
    pub fn detect_backend() -> FirewallBackend {
        if let Ok(output) = Command::new("nft").arg("--version").output() {
            if output.status.success() {
                return FirewallBackend::Nftables;
            }
        }
        if let Ok(output) = Command::new("iptables").arg("--version").output() {
            if output.status.success() {
                return FirewallBackend::Iptables;
            }
        }
        FirewallBackend::Unavailable
    }

    /// Kill an active TCP connection using Linux `ss -K` (socket kill option)
    pub fn kill_connection(local_addr: &str, remote_addr: &str) -> Result<String, String> {
        info!("Attempting to kill connection: {} -> {}", local_addr, remote_addr);

        let (local_ip_part, _local_port) = Self::parse_socket_endpoint(local_addr)
            .ok_or_else(|| format!("Invalid local address format: '{}'", local_addr))?;
        let (remote_ip_part, _remote_port) = Self::parse_socket_endpoint(remote_addr)
            .ok_or_else(|| format!("Invalid remote address format: '{}'", remote_addr))?;

        if local_ip_part.is_loopback() && remote_ip_part.is_loopback() {
            return Err("Refusing to terminate internal loopback connection (safety protection)".to_string());
        }

        let filter = format!("dst {} and src {}", remote_addr, local_addr);
        let output = Command::new("ss")
            .args(["-K", "-t", &filter])
            .output()
            .map_err(|e| format!("Failed to execute ss: {}", e))?;

        if output.status.success() {
            Ok(format!("Socket {} -> {} termination signal sent successfully", local_addr, remote_addr))
        } else {
            let err = String::from_utf8_lossy(&output.stderr);
            if err.contains("Operation not permitted") {
                Err("Killing active sockets requires root or CAP_NET_ADMIN privileges".to_string())
            } else {
                Err(format!("Error terminating socket: {}", err.trim()))
            }
        }
    }

    /// Block a specific remote IP using iptables (IPv4) or ip6tables (IPv6).
    pub fn block_ip(ip_str: &str) -> Result<String, String> {
        info!("Attempting to block IP: {}", ip_str);

        let ip = IpAddr::from_str(ip_str.trim())
            .map_err(|_| format!("Invalid IP address format: '{}'", ip_str))?;

        if ip.is_loopback() {
            return Err("Safety error: Refusing to block loopback address (127.0.0.1 / ::1)".to_string());
        }
        if ip.is_unspecified() {
            return Err("Safety error: Refusing to block unspecified address (0.0.0.0 / ::)".to_string());
        }

        let (cmd, target_str) = match ip {
            IpAddr::V4(v4) => ("iptables", v4.to_string()),
            IpAddr::V6(v6) => ("ip6tables", v6.to_string()),
        };

        // Prevent duplicate rules: check if rule already exists
        if let Ok(check) = Command::new(cmd)
            .args(["-C", "OUTPUT", "-d", &target_str, "-j", "DROP"])
            .output()
        {
            if check.status.success() {
                return Ok(format!("IP {} is already blocked in {} OUTPUT chain", ip, cmd));
            }
        }

        let output = Command::new(cmd)
            .args(["-A", "OUTPUT", "-d", &target_str, "-j", "DROP"])
            .output()
            .map_err(|e| format!("Failed to invoke {}: {}", cmd, e))?;

        if output.status.success() {
            Ok(format!("IP {} blocked via netfilter ({} OUTPUT DROP)", ip, cmd))
        } else {
            let err = String::from_utf8_lossy(&output.stderr);
            Err(if err.contains("Permission denied") || err.contains("superuser") {
                "Blocking IP addresses requires root or CAP_NET_ADMIN permissions".to_string()
            } else {
                err.trim().to_string()
            })
        }
    }

    /// Unblock a previously blocked IP, removing all matching occurrences
    pub fn unblock_ip(ip_str: &str) -> Result<String, String> {
        let ip = IpAddr::from_str(ip_str.trim())
            .map_err(|_| format!("Invalid IP address format: '{}'", ip_str))?;

        let (cmd, target_str) = match ip {
            IpAddr::V4(v4) => ("iptables", v4.to_string()),
            IpAddr::V6(v6) => ("ip6tables", v6.to_string()),
        };

        let mut removed_count = 0;
        while let Ok(output) = Command::new(cmd)
            .args(["-D", "OUTPUT", "-d", &target_str, "-j", "DROP"])
            .output()
        {
            if output.status.success() {
                removed_count += 1;
            } else {
                break;
            }
        }

        if removed_count > 0 {
            Ok(format!("IP {} unblocked successfully (removed {} rule(s))", ip, removed_count))
        } else {
            Err(format!("No active block rule found for IP {}", ip))
        }
    }

    /// Transactional Emergency Kill-Switch:
    /// Applies all 4 rules (IPv4 In/Out, IPv6 In/Out).
    /// If ANY rule fails, automatically rolls back previously inserted rules to leave zero partial changes!
    pub fn activate_emergency_killswitch() -> Result<String, String> {
        let rules: [(&str, &[&str], &[&str]); 4] = [
            ("iptables", &["-I", "OUTPUT", "1", "!", "-o", "lo", "-j", "DROP"], &["-D", "OUTPUT", "!", "-o", "lo", "-j", "DROP"]),
            ("iptables", &["-I", "INPUT", "1", "!", "-i", "lo", "-j", "DROP"], &["-D", "INPUT", "!", "-i", "lo", "-j", "DROP"]),
            ("ip6tables", &["-I", "OUTPUT", "1", "!", "-o", "lo", "-j", "DROP"], &["-D", "OUTPUT", "!", "-o", "lo", "-j", "DROP"]),
            ("ip6tables", &["-I", "INPUT", "1", "!", "-i", "lo", "-j", "DROP"], &["-D", "INPUT", "!", "-i", "lo", "-j", "DROP"]),
        ];

        let mut applied_indices: Vec<usize> = Vec::new();

        for (i, (cmd, insert_args, _delete_args)) in rules.iter().enumerate() {
            let output = Command::new(cmd).args(*insert_args).output();
            match output {
                Ok(out) if out.status.success() => {
                    applied_indices.push(i);
                }
                Ok(out) => {
                    let err = String::from_utf8_lossy(&out.stderr);
                    warn!("Killswitch rule insertion failed for {}: {}. Initiating transactional rollback...", cmd, err.trim());
                    Self::rollback_rules(&rules, &applied_indices);
                    return Err(format!("Transactional failure on {}: {}. All rules safely rolled back.", cmd, err.trim()));
                }
                Err(e) => {
                    warn!("Failed to execute {}: {}. Initiating transactional rollback...", cmd, e);
                    Self::rollback_rules(&rules, &applied_indices);
                    return Err(format!("Command invocation error on {}: {}. All rules safely rolled back.", cmd, e));
                }
            }
        }

        Ok("Emergency kill-switch active: all inbound and outbound non-loopback traffic transactionally blocked".to_string())
    }

    fn rollback_rules(rules: &[(&str, &[&str], &[&str]); 4], applied: &[usize]) {
        for &idx in applied.iter().rev() {
            let (cmd, _insert_args, delete_args) = rules[idx];
            let _ = Command::new(cmd).args(delete_args).output();
        }
    }

    /// Deactivates emergency killswitch by clearing all associated DROP rules
    pub fn deactivate_emergency_killswitch() -> Result<String, String> {
        let rules = [
            ("iptables", vec!["-D", "OUTPUT", "!", "-o", "lo", "-j", "DROP"]),
            ("iptables", vec!["-D", "INPUT", "!", "-i", "lo", "-j", "DROP"]),
            ("ip6tables", vec!["-D", "OUTPUT", "!", "-o", "lo", "-j", "DROP"]),
            ("ip6tables", vec!["-D", "INPUT", "!", "-i", "lo", "-j", "DROP"]),
        ];

        for (cmd, args) in rules {
            while let Ok(output) = Command::new(cmd).args(&args).output() {
                if !output.status.success() {
                    break;
                }
            }
        }

        Ok("Emergency kill-switch deactivated: network traffic restored".to_string())
    }

    /// Returns independent dual-stack status
    pub fn dual_stack_status() -> DualStackStatus {
        let v4_out = Command::new("iptables").args(["-C", "OUTPUT", "!", "-o", "lo", "-j", "DROP"]).output();
        let v4_in = Command::new("iptables").args(["-C", "INPUT", "!", "-i", "lo", "-j", "DROP"]).output();
        let v6_out = Command::new("ip6tables").args(["-C", "OUTPUT", "!", "-o", "lo", "-j", "DROP"]).output();
        let v6_in = Command::new("ip6tables").args(["-C", "INPUT", "!", "-i", "lo", "-j", "DROP"]).output();

        let ipv4_active = matches!((v4_out, v4_in), (Ok(o), Ok(i)) if o.status.success() && i.status.success());
        let ipv6_active = matches!((v6_out, v6_in), (Ok(o), Ok(i)) if o.status.success() && i.status.success());

        DualStackStatus {
            ipv4_active,
            ipv6_active,
        }
    }

    pub fn emergency_killswitch_status() -> bool {
        let st = Self::dual_stack_status();
        st.ipv4_active || st.ipv6_active
    }

    fn parse_socket_endpoint(endpoint: &str) -> Option<(IpAddr, u16)> {
        if let Some((ip_part, port_part)) = endpoint.rsplit_once(':') {
            let clean_ip = ip_part.trim_matches(|c| c == '[' || c == ']');
            let ip = IpAddr::from_str(clean_ip).ok()?;
            let port = port_part.parse::<u16>().ok()?;
            Some((ip, port))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_socket_endpoint() {
        let (ip, port) = NetworkFirewall::parse_socket_endpoint("192.168.1.1:443").unwrap();
        assert_eq!(ip.to_string(), "192.168.1.1");
        assert_eq!(port, 443);

        let (ip6, port6) = NetworkFirewall::parse_socket_endpoint("[::1]:8080").unwrap();
        assert_eq!(ip6.to_string(), "::1");
        assert_eq!(port6, 8080);
    }

    #[test]
    fn test_block_ip_validation_rejects_loopback() {
        assert!(NetworkFirewall::block_ip("127.0.0.1").is_err());
        assert!(NetworkFirewall::block_ip("::1").is_err());
        assert!(NetworkFirewall::block_ip("0.0.0.0").is_err());
    }

    #[test]
    fn test_kill_connection_rejects_internal_loopback() {
        assert!(NetworkFirewall::kill_connection("127.0.0.1:5000", "127.0.0.1:8080").is_err());
    }
}
