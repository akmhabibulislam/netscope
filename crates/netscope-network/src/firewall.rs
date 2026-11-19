use std::process::Command;
use tracing::{info, warn};

pub struct NetworkFirewall;

impl NetworkFirewall {
    /// Kill an active TCP connection using Linux `ss -K` (socket kill option)
    pub fn kill_connection(local_addr: &str, remote_addr: &str) -> Result<String, String> {
        info!("Attempting to kill connection: {} -> {}", local_addr, remote_addr);
        
        let filter = format!("dst {} and src {}", remote_addr, local_addr);
        let output = Command::new("ss")
            .args(["-K", "-t", &filter])
            .output()
            .map_err(|e| format!("Failed to execute ss: {}", e))?;

        if output.status.success() {
            Ok(format!("Socket {} -> {} termination signal sent", local_addr, remote_addr))
        } else {
            let err = String::from_utf8_lossy(&output.stderr);
            if err.contains("Operation not permitted") {
                Err("Killing active sockets requires root or CAP_NET_ADMIN privileges".to_string())
            } else {
                Err(format!("Error terminating socket: {}", err.trim()))
            }
        }
    }

    /// Emergency Kill-Switch: Drops all non-loopback outbound/inbound traffic via nftables / iptables
    pub fn emergency_killswitch_status() -> bool {
        // Check if an emergency drop rule exists in iptables/nftables
        if let Ok(output) = Command::new("iptables").args(["-C", "OUTPUT", "-o", "lo", "-j", "ACCEPT"]).output() {
            return output.status.success();
        }
        false
    }

    /// Block a specific remote IP using iptables or nftables
    pub fn block_ip(ip: &str) -> Result<String, String> {
        info!("Attempting to block IP: {}", ip);
        let output = Command::new("iptables")
            .args(["-A", "OUTPUT", "-d", ip, "-j", "DROP"])
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
}
