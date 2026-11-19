use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;
use tracing::info;

pub struct NetworkFirewall;

impl NetworkFirewall {
    /// Kill an active TCP connection using Linux `ss -K` (socket kill option)
    /// Validates IP address inputs before invoking the Linux command.
    pub fn kill_connection(local_addr: &str, remote_addr: &str) -> Result<String, String> {
        info!("Attempting to kill connection: {} -> {}", local_addr, remote_addr);

        // Input validation: ensure addresses match IP:Port syntax safely
        let (local_ip_part, _local_port) = Self::parse_socket_endpoint(local_addr)
            .ok_or_else(|| format!("Invalid local address format: '{}'", local_addr))?;
        let (remote_ip_part, _remote_port) = Self::parse_socket_endpoint(remote_addr)
            .ok_or_else(|| format!("Invalid remote address format: '{}'", remote_addr))?;

        // Protect against accidental termination of loopback core services
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

    /// Block a specific remote IP using iptables or nftables after strict IP validation
    pub fn block_ip(ip_str: &str) -> Result<String, String> {
        info!("Attempting to block IP: {}", ip_str);

        // Strict IP address validation
        let ip = IpAddr::from_str(ip_str.trim())
            .map_err(|_| format!("Invalid IP address format: '{}'", ip_str))?;

        // Safety guards: prevent accidental network bricking
        if ip.is_loopback() {
            return Err("Safety error: Refusing to block loopback address (127.0.0.1 / ::1)".to_string());
        }
        if ip.is_unspecified() {
            return Err("Safety error: Refusing to block unspecified address (0.0.0.0 / ::)".to_string());
        }

        let output = Command::new("iptables")
            .args(["-A", "OUTPUT", "-d", &ip.to_string(), "-j", "DROP"])
            .output()
            .map_err(|e| format!("Failed to invoke iptables: {}", e))?;

        if output.status.success() {
            Ok(format!("IP {} blocked via netfilter (OUTPUT DROP)", ip))
        } else {
            let err = String::from_utf8_lossy(&output.stderr);
            Err(if err.contains("Permission denied") || err.contains("superuser") {
                "Blocking IP addresses requires root or CAP_NET_ADMIN permissions".to_string()
            } else {
                err.trim().to_string()
            })
        }
    }

    /// Unblock a previously blocked IP
    pub fn unblock_ip(ip_str: &str) -> Result<String, String> {
        let ip = IpAddr::from_str(ip_str.trim())
            .map_err(|_| format!("Invalid IP address format: '{}'", ip_str))?;

        let output = Command::new("iptables")
            .args(["-D", "OUTPUT", "-d", &ip.to_string(), "-j", "DROP"])
            .output()
            .map_err(|e| format!("Failed to invoke iptables: {}", e))?;

        if output.status.success() {
            Ok(format!("IP {} unblocked successfully", ip))
        } else {
            let err = String::from_utf8_lossy(&output.stderr);
            Err(err.trim().to_string())
        }
    }

    /// Emergency Kill-Switch: Drops all non-loopback outbound traffic
    pub fn activate_emergency_killswitch() -> Result<String, String> {
        // Drop all output except to loopback (lo)
        let output = Command::new("iptables")
            .args(["-I", "OUTPUT", "1", "!", "-o", "lo", "-j", "DROP"])
            .output()
            .map_err(|e| format!("Failed to invoke iptables: {}", e))?;

        if output.status.success() {
            Ok("Emergency kill-switch active: all outbound non-loopback traffic blocked".to_string())
        } else {
            let err = String::from_utf8_lossy(&output.stderr);
            Err(err.trim().to_string())
        }
    }

    /// Deactivate emergency killswitch
    pub fn deactivate_emergency_killswitch() -> Result<String, String> {
        let output = Command::new("iptables")
            .args(["-D", "OUTPUT", "!", "-o", "lo", "-j", "DROP"])
            .output()
            .map_err(|e| format!("Failed to invoke iptables: {}", e))?;

        if output.status.success() {
            Ok("Emergency kill-switch deactivated".to_string())
        } else {
            let err = String::from_utf8_lossy(&output.stderr);
            Err(err.trim().to_string())
        }
    }

    /// Checks if the emergency killswitch rule is currently present in iptables
    pub fn emergency_killswitch_status() -> bool {
        if let Ok(output) = Command::new("iptables")
            .args(["-C", "OUTPUT", "!", "-o", "lo", "-j", "DROP"])
            .output()
        {
            return output.status.success();
        }
        false
    }

    fn parse_socket_endpoint(endpoint: &str) -> Option<(IpAddr, u16)> {
        // Handles 1.2.3.4:80 and [::1]:80
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
