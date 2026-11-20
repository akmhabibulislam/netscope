use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;
use tracing::{info, warn};

/// Trait abstracting firewall command execution for deterministic mocking and host safety
pub trait FirewallCommandRunner: Send + Sync {
    fn execute(&self, cmd: &str, args: &[&str]) -> Result<CommandResult, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

pub struct SystemCommandRunner;

impl FirewallCommandRunner for SystemCommandRunner {
    fn execute(&self, cmd: &str, args: &[&str]) -> Result<CommandResult, String> {
        let output = Command::new(cmd)
            .args(args)
            .output()
            .map_err(|e| format!("Failed to execute '{}': {}", cmd, e))?;
        Ok(CommandResult {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    Nftables,
    Iptables,
    Unavailable,
}

impl std::fmt::Display for FirewallBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nftables => write!(f, "nftables"),
            Self::Iptables => write!(f, "iptables/ip6tables"),
            Self::Unavailable => write!(f, "Unavailable"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DualStackState {
    FullyActive,
    IPv4Only,
    IPv6Only,
    Inactive,
    PartiallyConfigured,
    Unknown,
}

impl std::fmt::Display for DualStackState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FullyActive => write!(f, "Fully Active (IPv4 & IPv6)"),
            Self::IPv4Only => write!(f, "IPv4 Only Active"),
            Self::IPv6Only => write!(f, "IPv6 Only Active"),
            Self::Inactive => write!(f, "Inactive"),
            Self::PartiallyConfigured => write!(f, "Partially Configured"),
            Self::Unknown => write!(f, "Unknown / Verification Error"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DualStackStatus {
    pub ipv4_active: bool,
    pub ipv6_active: bool,
    pub state: DualStackState,
}

pub struct NetworkFirewall;

type FirewallStep<'a> = (&'a str, &'a [&'a str], Option<&'a [&'a str]>);

impl NetworkFirewall {
    const CHAIN_IN: &'static str = "NETSCOPE_IN";
    const CHAIN_OUT: &'static str = "NETSCOPE_OUT";
    const CHAIN_BLOCK: &'static str = "NETSCOPE_BLOCK";

    /// Detect active Linux firewall backend without mixing commands
    pub fn detect_backend() -> FirewallBackend {
        Self::detect_backend_with(&SystemCommandRunner)
    }

    pub fn detect_backend_with(runner: &dyn FirewallCommandRunner) -> FirewallBackend {
        if let Ok(res) = runner.execute("nft", &["--version"]) {
            if res.success {
                return FirewallBackend::Nftables;
            }
        }
        if let Ok(res) = runner.execute("iptables", &["--version"]) {
            if res.success {
                return FirewallBackend::Iptables;
            }
        }
        FirewallBackend::Unavailable
    }

    /// Kill an active TCP connection using Linux `ss -K`
    pub fn kill_connection(local_addr: &str, remote_addr: &str) -> Result<String, String> {
        Self::kill_connection_with(&SystemCommandRunner, local_addr, remote_addr)
    }

    pub fn kill_connection_with(
        runner: &dyn FirewallCommandRunner,
        local_addr: &str,
        remote_addr: &str,
    ) -> Result<String, String> {
        info!(
            "Attempting to kill connection: {} -> {}",
            local_addr, remote_addr
        );

        let (local_ip_part, _local_port) = Self::parse_socket_endpoint(local_addr)
            .ok_or_else(|| format!("Invalid local address format: '{}'", local_addr))?;
        let (remote_ip_part, _remote_port) = Self::parse_socket_endpoint(remote_addr)
            .ok_or_else(|| format!("Invalid remote address format: '{}'", remote_addr))?;

        if local_ip_part.is_loopback() && remote_ip_part.is_loopback() {
            return Err(
                "Refusing to terminate internal loopback connection (safety protection)"
                    .to_string(),
            );
        }

        let filter = format!("dst {} and src {}", remote_addr, local_addr);
        let res = runner.execute("ss", &["-K", "-t", &filter])?;

        if res.success {
            Ok(format!(
                "Socket {} -> {} termination signal sent successfully",
                local_addr, remote_addr
            ))
        } else if res.stderr.contains("Operation not permitted") {
            Err("Killing active sockets requires root or CAP_NET_ADMIN privileges".to_string())
        } else {
            Err(format!("Error terminating socket: {}", res.stderr.trim()))
        }
    }

    /// Block a specific remote IP using dedicated NetScope application-owned chain
    pub fn block_ip(ip_str: &str) -> Result<String, String> {
        Self::block_ip_with(&SystemCommandRunner, ip_str)
    }

    pub fn block_ip_with(
        runner: &dyn FirewallCommandRunner,
        ip_str: &str,
    ) -> Result<String, String> {
        info!("Attempting to block IP: {}", ip_str);

        let ip = IpAddr::from_str(ip_str.trim())
            .map_err(|_| format!("Invalid IP address format: '{}'", ip_str))?;

        if ip.is_loopback() {
            return Err(
                "Safety error: Refusing to block loopback address (127.0.0.1 / ::1)".to_string(),
            );
        }
        if ip.is_unspecified() {
            return Err(
                "Safety error: Refusing to block unspecified address (0.0.0.0 / ::)".to_string(),
            );
        }

        let (cmd, target_str) = match ip {
            IpAddr::V4(v4) => ("iptables", v4.to_string()),
            IpAddr::V6(v6) => ("ip6tables", v6.to_string()),
        };

        // 1. Ensure application-owned block chain exists
        let create_res = runner.execute(cmd, &["-N", Self::CHAIN_BLOCK]);
        if let Ok(res) = create_res {
            if !res.success && !res.stderr.contains("Chain already exists") {
                return Err(Self::format_perm_err(&res.stderr, cmd));
            }
        }

        // 2. Ensure jump rule in OUTPUT exists
        let jump_needed = !runner
            .execute(cmd, &["-C", "OUTPUT", "-j", Self::CHAIN_BLOCK])?
            .success;

        if jump_needed {
            let add_jump = runner.execute(cmd, &["-I", "OUTPUT", "1", "-j", Self::CHAIN_BLOCK])?;
            if !add_jump.success {
                return Err(Self::format_perm_err(&add_jump.stderr, cmd));
            }
        }

        // 3. Prevent duplicates: check if rule already exists in our dedicated chain
        let check_rule = runner.execute(
            cmd,
            &["-C", Self::CHAIN_BLOCK, "-d", &target_str, "-j", "DROP"],
        );
        if let Ok(res) = check_rule {
            if res.success {
                return Ok(format!(
                    "IP {} is already blocked in NetScope {} chain",
                    ip,
                    Self::CHAIN_BLOCK
                ));
            }
        }

        // 4. Add drop rule to dedicated chain
        let output = runner.execute(
            cmd,
            &["-A", Self::CHAIN_BLOCK, "-d", &target_str, "-j", "DROP"],
        )?;

        if output.success {
            Ok(format!(
                "IP {} blocked via NetScope netfilter chain ({} {} DROP)",
                ip,
                cmd,
                Self::CHAIN_BLOCK
            ))
        } else {
            Err(Self::format_perm_err(&output.stderr, cmd))
        }
    }

    /// Unblock a previously blocked IP from NetScope application-owned chain
    pub fn unblock_ip(ip_str: &str) -> Result<String, String> {
        Self::unblock_ip_with(&SystemCommandRunner, ip_str)
    }

    pub fn unblock_ip_with(
        runner: &dyn FirewallCommandRunner,
        ip_str: &str,
    ) -> Result<String, String> {
        let ip = IpAddr::from_str(ip_str.trim())
            .map_err(|_| format!("Invalid IP address format: '{}'", ip_str))?;

        let (cmd, target_str) = match ip {
            IpAddr::V4(v4) => ("iptables", v4.to_string()),
            IpAddr::V6(v6) => ("ip6tables", v6.to_string()),
        };

        let mut removed_count = 0;
        loop {
            let res = runner.execute(
                cmd,
                &["-D", Self::CHAIN_BLOCK, "-d", &target_str, "-j", "DROP"],
            );
            match res {
                Ok(out) if out.success => removed_count += 1,
                _ => break,
            }
        }

        if removed_count > 0 {
            Ok(format!(
                "IP {} unblocked successfully (removed {} rule(s) from {})",
                ip,
                removed_count,
                Self::CHAIN_BLOCK
            ))
        } else {
            Err(format!(
                "No active block rule found for IP {} in NetScope chain",
                ip
            ))
        }
    }

    /// Transactional Emergency Kill-Switch:
    /// Isolates non-loopback network communication using dedicated application-owned chains.
    /// If ANY operation fails, rolls back all applied changes and verifies the rollback.
    pub fn activate_emergency_killswitch() -> Result<String, String> {
        let backend = Self::detect_backend();
        Self::activate_emergency_killswitch_with(&SystemCommandRunner, backend)
    }

    pub fn activate_emergency_killswitch_with(
        runner: &dyn FirewallCommandRunner,
        backend: FirewallBackend,
    ) -> Result<String, String> {
        match backend {
            FirewallBackend::Nftables => Self::activate_killswitch_nftables(runner),
            FirewallBackend::Iptables => Self::activate_killswitch_iptables(runner),
            FirewallBackend::Unavailable => Err(
                "No supported firewall backend found. Ensure iptables or nftables is installed."
                    .to_string(),
            ),
        }
    }

    fn activate_killswitch_iptables(runner: &dyn FirewallCommandRunner) -> Result<String, String> {
        // Steps to apply: (command, args, undo_args)
        let steps: [FirewallStep<'static>; 8] = [
            // IPv4 custom chains
            (
                "iptables",
                &["-N", Self::CHAIN_IN],
                Some(&["-X", Self::CHAIN_IN]),
            ),
            (
                "iptables",
                &["-N", Self::CHAIN_OUT],
                Some(&["-X", Self::CHAIN_OUT]),
            ),
            // IPv4 jumps from root chains to NetScope chains
            (
                "iptables",
                &["-I", "INPUT", "1", "-j", Self::CHAIN_IN],
                Some(&["-D", "INPUT", "-j", Self::CHAIN_IN]),
            ),
            (
                "iptables",
                &["-I", "OUTPUT", "1", "-j", Self::CHAIN_OUT],
                Some(&["-D", "OUTPUT", "-j", Self::CHAIN_OUT]),
            ),
            // IPv4 drop rules inside NetScope chains
            (
                "iptables",
                &["-I", Self::CHAIN_IN, "1", "!", "-i", "lo", "-j", "DROP"],
                Some(&["-D", Self::CHAIN_IN, "!", "-i", "lo", "-j", "DROP"]),
            ),
            (
                "iptables",
                &["-I", Self::CHAIN_OUT, "1", "!", "-o", "lo", "-j", "DROP"],
                Some(&["-D", Self::CHAIN_OUT, "!", "-o", "lo", "-j", "DROP"]),
            ),
            // IPv6 custom chains
            (
                "ip6tables",
                &["-N", Self::CHAIN_IN],
                Some(&["-X", Self::CHAIN_IN]),
            ),
            (
                "ip6tables",
                &["-N", Self::CHAIN_OUT],
                Some(&["-X", Self::CHAIN_OUT]),
            ),
        ];

        let steps_ipv6_rules: [FirewallStep<'static>; 4] = [
            (
                "ip6tables",
                &["-I", "INPUT", "1", "-j", Self::CHAIN_IN],
                Some(&["-D", "INPUT", "-j", Self::CHAIN_IN]),
            ),
            (
                "ip6tables",
                &["-I", "OUTPUT", "1", "-j", Self::CHAIN_OUT],
                Some(&["-D", "OUTPUT", "-j", Self::CHAIN_OUT]),
            ),
            (
                "ip6tables",
                &["-I", Self::CHAIN_IN, "1", "!", "-i", "lo", "-j", "DROP"],
                Some(&["-D", Self::CHAIN_IN, "!", "-i", "lo", "-j", "DROP"]),
            ),
            (
                "ip6tables",
                &["-I", Self::CHAIN_OUT, "1", "!", "-o", "lo", "-j", "DROP"],
                Some(&["-D", Self::CHAIN_OUT, "!", "-o", "lo", "-j", "DROP"]),
            ),
        ];

        let mut applied_undos: Vec<(&str, &[&str])> = Vec::new();

        for (cmd, args, undo) in steps.iter().chain(steps_ipv6_rules.iter()) {
            let res = runner.execute(cmd, args);
            match res {
                Ok(out) => {
                    if out.success {
                        if let Some(u) = undo {
                            applied_undos.push((cmd, *u));
                        }
                    } else if args[0] == "-N" && out.stderr.contains("Chain already exists") {
                        // Chain exists from earlier; still record undo flush/cleanup if needed
                    } else {
                        let err_msg =
                            format!("{} {} failed: {}", cmd, args.join(" "), out.stderr.trim());
                        warn!(
                            "Killswitch step failed: {}. Initiating rollback...",
                            err_msg
                        );
                        let rollback_ok = Self::execute_and_verify_rollback(runner, &applied_undos);
                        if rollback_ok {
                            return Err(format!(
                                "Emergency killswitch activation failed: {}. All applied rules were transactionally rolled back and verified.",
                                err_msg
                            ));
                        } else {
                            return Err(format!(
                                "CRITICAL: Activation failed ({}) AND rollback could not restore clean state. Manual firewall inspection required.",
                                err_msg
                            ));
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Invocation error during killswitch activation: {}. Initiating rollback...",
                        e
                    );
                    let rollback_ok = Self::execute_and_verify_rollback(runner, &applied_undos);
                    if rollback_ok {
                        return Err(format!(
                            "Invocation error: {}. All applied rules were transactionally rolled back and verified.",
                            e
                        ));
                    } else {
                        return Err(format!(
                            "CRITICAL: Invocation error ({}) AND rollback could not restore clean state. Manual firewall inspection required.",
                            e
                        ));
                    }
                }
            }
        }

        // Verify activation
        let status = Self::dual_stack_status_with(runner, FirewallBackend::Iptables);
        if status.state == DualStackState::FullyActive {
            Ok("Emergency kill-switch active: all inbound and outbound non-loopback traffic transactionally blocked (IPv4 + IPv6 verified)".to_string())
        } else {
            // Did not achieve fully active state
            let rollback_ok = Self::execute_and_verify_rollback(runner, &applied_undos);
            if rollback_ok {
                Err("Killswitch verification failed after application. Transactionally rolled back all changes.".to_string())
            } else {
                Err("CRITICAL: Killswitch verification failed AND rollback incomplete. Inconsistent firewall state detected.".to_string())
            }
        }
    }

    fn activate_killswitch_nftables(runner: &dyn FirewallCommandRunner) -> Result<String, String> {
        let commands: [(&str, &[&str]); 5] = [
            ("nft", &["add", "table", "inet", "netscope"]),
            (
                "nft",
                &[
                    "add",
                    "chain",
                    "inet",
                    "netscope",
                    "input",
                    "{ type filter hook input priority -10; policy accept; }",
                ],
            ),
            (
                "nft",
                &[
                    "add",
                    "chain",
                    "inet",
                    "netscope",
                    "output",
                    "{ type filter hook output priority -10; policy accept; }",
                ],
            ),
            (
                "nft",
                &[
                    "add", "rule", "inet", "netscope", "input", "iif", "!=", "lo", "drop",
                ],
            ),
            (
                "nft",
                &[
                    "add", "rule", "inet", "netscope", "output", "oif", "!=", "lo", "drop",
                ],
            ),
        ];

        let mut applied_count = 0;
        for (cmd, args) in &commands {
            let res = runner.execute(cmd, args);
            match res {
                Ok(out) if out.success => {
                    applied_count += 1;
                }
                Ok(out) => {
                    warn!(
                        "nftables activation failed at step {}: {}",
                        applied_count,
                        out.stderr.trim()
                    );
                    let _ = runner.execute("nft", &["delete", "table", "inet", "netscope"]);
                    return Err(format!(
                        "nftables activation failed: {}. Table transactionally removed.",
                        out.stderr.trim()
                    ));
                }
                Err(e) => {
                    warn!("nftables invocation error: {}", e);
                    let _ = runner.execute("nft", &["delete", "table", "inet", "netscope"]);
                    return Err(format!(
                        "nftables invocation error: {}. Table transactionally removed.",
                        e
                    ));
                }
            }
        }

        Ok("Emergency kill-switch active: all inbound and outbound non-loopback traffic blocked via nftables inet table".to_string())
    }

    fn execute_and_verify_rollback(
        runner: &dyn FirewallCommandRunner,
        undos: &[(&str, &[&str])],
    ) -> bool {
        let mut all_succeeded = true;
        for (cmd, args) in undos.iter().rev() {
            if let Ok(res) = runner.execute(cmd, args) {
                if !res.success && !res.stderr.contains("No chain/target/match by that name") {
                    all_succeeded = false;
                }
            } else {
                all_succeeded = false;
            }
        }

        // Verification check: ensure no NetScope jump rules remain
        let v4_in = runner.execute("iptables", &["-C", "INPUT", "-j", Self::CHAIN_IN]);
        let v4_out = runner.execute("iptables", &["-C", "OUTPUT", "-j", Self::CHAIN_OUT]);
        let v6_in = runner.execute("ip6tables", &["-C", "INPUT", "-j", Self::CHAIN_IN]);
        let v6_out = runner.execute("ip6tables", &["-C", "OUTPUT", "-j", Self::CHAIN_OUT]);

        let has_v4_jump =
            matches!(v4_in, Ok(r) if r.success) || matches!(v4_out, Ok(r) if r.success);
        let has_v6_jump =
            matches!(v6_in, Ok(r) if r.success) || matches!(v6_out, Ok(r) if r.success);

        all_succeeded && !has_v4_jump && !has_v6_jump
    }

    /// Deactivates emergency killswitch by clearing application-owned chains and jump rules
    pub fn deactivate_emergency_killswitch() -> Result<String, String> {
        let backend = Self::detect_backend();
        Self::deactivate_emergency_killswitch_with(&SystemCommandRunner, backend)
    }

    pub fn deactivate_emergency_killswitch_with(
        runner: &dyn FirewallCommandRunner,
        backend: FirewallBackend,
    ) -> Result<String, String> {
        match backend {
            FirewallBackend::Nftables => {
                let res = runner.execute("nft", &["delete", "table", "inet", "netscope"]);
                match res {
                    Ok(out) if out.success || out.stderr.contains("No such file or directory") => {
                        Ok("Emergency kill-switch deactivated: nftables table removed".to_string())
                    }
                    Ok(out) => Err(format!(
                        "Failed to delete nftables table: {}",
                        out.stderr.trim()
                    )),
                    Err(e) => Err(format!("Failed to invoke nft: {}", e)),
                }
            }
            FirewallBackend::Iptables => {
                // Delete jumps first
                let _ = runner.execute("iptables", &["-D", "INPUT", "-j", Self::CHAIN_IN]);
                let _ = runner.execute("iptables", &["-D", "OUTPUT", "-j", Self::CHAIN_OUT]);
                let _ = runner.execute("ip6tables", &["-D", "INPUT", "-j", Self::CHAIN_IN]);
                let _ = runner.execute("ip6tables", &["-D", "OUTPUT", "-j", Self::CHAIN_OUT]);

                // Flush custom chains
                let _ = runner.execute("iptables", &["-F", Self::CHAIN_IN]);
                let _ = runner.execute("iptables", &["-F", Self::CHAIN_OUT]);
                let _ = runner.execute("ip6tables", &["-F", Self::CHAIN_IN]);
                let _ = runner.execute("ip6tables", &["-F", Self::CHAIN_OUT]);

                // Delete custom chains
                let _ = runner.execute("iptables", &["-X", Self::CHAIN_IN]);
                let _ = runner.execute("iptables", &["-X", Self::CHAIN_OUT]);
                let _ = runner.execute("ip6tables", &["-X", Self::CHAIN_IN]);
                let _ = runner.execute("ip6tables", &["-X", Self::CHAIN_OUT]);

                // Verify deactivation
                let status = Self::dual_stack_status_with(runner, FirewallBackend::Iptables);
                if status.state == DualStackState::Inactive {
                    Ok("Emergency kill-switch deactivated: network traffic restored".to_string())
                } else {
                    Err(format!(
                        "Deactivation verification failed: firewall state is {}",
                        status.state
                    ))
                }
            }
            FirewallBackend::Unavailable => Err("No supported firewall backend found".to_string()),
        }
    }

    /// Returns truthful independent dual-stack status
    pub fn dual_stack_status() -> DualStackStatus {
        let backend = Self::detect_backend();
        Self::dual_stack_status_with(&SystemCommandRunner, backend)
    }

    pub fn dual_stack_status_with(
        runner: &dyn FirewallCommandRunner,
        backend: FirewallBackend,
    ) -> DualStackStatus {
        if backend == FirewallBackend::Nftables {
            let list = runner.execute("nft", &["list", "table", "inet", "netscope"]);
            if let Ok(res) = list {
                if res.success
                    && res.stdout.contains("iif != \"lo\" drop")
                    && res.stdout.contains("oif != \"lo\" drop")
                {
                    return DualStackStatus {
                        ipv4_active: true,
                        ipv6_active: true,
                        state: DualStackState::FullyActive,
                    };
                }
            }
            return DualStackStatus {
                ipv4_active: false,
                ipv6_active: false,
                state: DualStackState::Inactive,
            };
        }

        // Iptables checks
        let v4_out_jump = runner.execute("iptables", &["-C", "OUTPUT", "-j", Self::CHAIN_OUT]);
        let v4_in_jump = runner.execute("iptables", &["-C", "INPUT", "-j", Self::CHAIN_IN]);
        let v4_out_rule = runner.execute(
            "iptables",
            &["-C", Self::CHAIN_OUT, "!", "-o", "lo", "-j", "DROP"],
        );
        let v4_in_rule = runner.execute(
            "iptables",
            &["-C", Self::CHAIN_IN, "!", "-i", "lo", "-j", "DROP"],
        );

        let v6_out_jump = runner.execute("ip6tables", &["-C", "OUTPUT", "-j", Self::CHAIN_OUT]);
        let v6_in_jump = runner.execute("ip6tables", &["-C", "INPUT", "-j", Self::CHAIN_IN]);
        let v6_out_rule = runner.execute(
            "ip6tables",
            &["-C", Self::CHAIN_OUT, "!", "-o", "lo", "-j", "DROP"],
        );
        let v6_in_rule = runner.execute(
            "ip6tables",
            &["-C", Self::CHAIN_IN, "!", "-i", "lo", "-j", "DROP"],
        );

        let is_ok = |r: &Result<CommandResult, String>| matches!(r, Ok(out) if out.success);

        let v4_all =
            is_ok(&v4_out_jump) && is_ok(&v4_in_jump) && is_ok(&v4_out_rule) && is_ok(&v4_in_rule);
        let v6_all =
            is_ok(&v6_out_jump) && is_ok(&v6_in_jump) && is_ok(&v6_out_rule) && is_ok(&v6_in_rule);

        let v4_any =
            is_ok(&v4_out_jump) || is_ok(&v4_in_jump) || is_ok(&v4_out_rule) || is_ok(&v4_in_rule);
        let v6_any =
            is_ok(&v6_out_jump) || is_ok(&v6_in_jump) || is_ok(&v6_out_rule) || is_ok(&v6_in_rule);

        let state = if v4_all && v6_all {
            DualStackState::FullyActive
        } else if v4_all && !v6_any {
            DualStackState::IPv4Only
        } else if v6_all && !v4_any {
            DualStackState::IPv6Only
        } else if !v4_any && !v6_any {
            DualStackState::Inactive
        } else {
            DualStackState::PartiallyConfigured
        };

        DualStackStatus {
            ipv4_active: v4_all,
            ipv6_active: v6_all,
            state,
        }
    }

    /// Overall killswitch status returns true ONLY if fully active across IPv4 and IPv6
    pub fn emergency_killswitch_status() -> bool {
        Self::dual_stack_status().state == DualStackState::FullyActive
    }

    fn format_perm_err(stderr: &str, cmd: &str) -> String {
        let err = stderr.trim();
        if err.contains("Permission denied")
            || err.contains("superuser")
            || err.contains("Operation not permitted")
        {
            format!(
                "Firewall operation with {} requires root or CAP_NET_ADMIN privileges",
                cmd
            )
        } else {
            err.to_string()
        }
    }

    pub fn parse_socket_endpoint(endpoint: &str) -> Option<(IpAddr, u16)> {
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
    use std::sync::Mutex;

    type MockHandler = Box<dyn Fn(&str, &[&str]) -> Result<CommandResult, String> + Send + Sync>;

    pub struct MockCommandRunner {
        pub executed: Mutex<Vec<String>>,
        pub handler: MockHandler,
    }

    impl FirewallCommandRunner for MockCommandRunner {
        fn execute(&self, cmd: &str, args: &[&str]) -> Result<CommandResult, String> {
            let line = format!("{} {}", cmd, args.join(" "));
            self.executed.lock().unwrap().push(line);
            (self.handler)(cmd, args)
        }
    }

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

    #[test]
    fn test_successful_activation_iptables() {
        let runner = MockCommandRunner {
            executed: Mutex::new(Vec::new()),
            handler: Box::new(|_cmd, _args| {
                Ok(CommandResult {
                    success: true,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            }),
        };

        let res =
            NetworkFirewall::activate_emergency_killswitch_with(&runner, FirewallBackend::Iptables);
        assert!(res.is_ok());
        let executed = runner.executed.lock().unwrap();
        // Verify custom chains NETSCOPE_IN and NETSCOPE_OUT were created
        assert!(executed
            .iter()
            .any(|c| c.contains("iptables -N NETSCOPE_IN")));
        assert!(executed
            .iter()
            .any(|c| c.contains("iptables -N NETSCOPE_OUT")));
        assert!(executed
            .iter()
            .any(|c| c.contains("ip6tables -N NETSCOPE_IN")));
        assert!(executed
            .iter()
            .any(|c| c.contains("ip6tables -N NETSCOPE_OUT")));
    }

    #[test]
    fn test_activation_rollback_on_single_rule_failure() {
        let active_rules = std::sync::Arc::new(Mutex::new(std::collections::HashSet::new()));
        let active_clone = active_rules.clone();

        let runner = MockCommandRunner {
            executed: Mutex::new(Vec::new()),
            handler: Box::new(move |cmd, args| {
                if cmd == "ip6tables"
                    && args.contains(&"INPUT")
                    && args.contains(&"-j")
                    && args.contains(&"-I")
                {
                    return Ok(CommandResult {
                        success: false,
                        stdout: String::new(),
                        stderr: "Permission denied inserting rule".to_string(),
                    });
                }

                let mut set = active_clone.lock().unwrap();
                if args.contains(&"-I") {
                    let key = format!("{} {}", cmd, args.join(" "));
                    set.insert(key);
                    Ok(CommandResult {
                        success: true,
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                } else if args.contains(&"-D") {
                    let target = args.last().unwrap_or(&"");
                    set.retain(|r| !r.contains(target));
                    Ok(CommandResult {
                        success: true,
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                } else if args.contains(&"-C") {
                    let target = args.last().unwrap_or(&"");
                    let exists = set.iter().any(|r| r.contains(target));
                    Ok(CommandResult {
                        success: exists,
                        stdout: String::new(),
                        stderr: if exists {
                            String::new()
                        } else {
                            "Rule not found".to_string()
                        },
                    })
                } else {
                    Ok(CommandResult {
                        success: true,
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                }
            }),
        };

        let res =
            NetworkFirewall::activate_emergency_killswitch_with(&runner, FirewallBackend::Iptables);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.contains("transactionally rolled back"));

        let executed = runner.executed.lock().unwrap();
        // Verify rollback actions deleted previously inserted IPv4 rules
        assert!(executed
            .iter()
            .any(|c| c.contains("iptables -D INPUT -j NETSCOPE_IN")));
        assert!(executed
            .iter()
            .any(|c| c.contains("iptables -D OUTPUT -j NETSCOPE_OUT")));
    }

    #[test]
    fn test_rollback_failure_reports_critical_state() {
        let runner = MockCommandRunner {
            executed: Mutex::new(Vec::new()),
            handler: Box::new(|cmd, args| {
                // Fail on rule 5, then also fail during rollback deletion
                if cmd == "iptables" && args.contains(&"-D") {
                    Ok(CommandResult {
                        success: false,
                        stdout: String::new(),
                        stderr: "Cannot delete rule".to_string(),
                    })
                } else if cmd == "ip6tables" {
                    Ok(CommandResult {
                        success: false,
                        stdout: String::new(),
                        stderr: "ip6tables error".to_string(),
                    })
                } else {
                    Ok(CommandResult {
                        success: true,
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                }
            }),
        };

        let res =
            NetworkFirewall::activate_emergency_killswitch_with(&runner, FirewallBackend::Iptables);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.contains("CRITICAL") || err.contains("could not restore clean state"));
    }

    #[test]
    fn test_repeated_activation_is_idempotent() {
        let runner = MockCommandRunner {
            executed: Mutex::new(Vec::new()),
            handler: Box::new(|_cmd, args| {
                if args.contains(&"-N") {
                    // Chain already exists
                    Ok(CommandResult {
                        success: false,
                        stdout: String::new(),
                        stderr: "Chain already exists".to_string(),
                    })
                } else {
                    Ok(CommandResult {
                        success: true,
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                }
            }),
        };

        let res1 =
            NetworkFirewall::activate_emergency_killswitch_with(&runner, FirewallBackend::Iptables);
        assert!(res1.is_ok());

        let res2 =
            NetworkFirewall::activate_emergency_killswitch_with(&runner, FirewallBackend::Iptables);
        assert!(res2.is_ok());
    }

    #[test]
    fn test_repeated_deactivation_is_safe() {
        let runner = MockCommandRunner {
            executed: Mutex::new(Vec::new()),
            handler: Box::new(|_cmd, args| {
                // Check queries report false/not found when inactive
                if args.contains(&"-C") {
                    Ok(CommandResult {
                        success: false,
                        stdout: String::new(),
                        stderr: "Bad rule".to_string(),
                    })
                } else {
                    Ok(CommandResult {
                        success: true,
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                }
            }),
        };

        let res = NetworkFirewall::deactivate_emergency_killswitch_with(
            &runner,
            FirewallBackend::Iptables,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_dual_stack_status_distinguishes_ipv4_only() {
        let runner = MockCommandRunner {
            executed: Mutex::new(Vec::new()),
            handler: Box::new(|cmd, _args| {
                if cmd == "iptables" {
                    Ok(CommandResult {
                        success: true,
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                } else {
                    Ok(CommandResult {
                        success: false,
                        stdout: String::new(),
                        stderr: "No rule".to_string(),
                    })
                }
            }),
        };

        let status = NetworkFirewall::dual_stack_status_with(&runner, FirewallBackend::Iptables);
        assert_eq!(status.state, DualStackState::IPv4Only);
        assert!(status.ipv4_active);
        assert!(!status.ipv6_active);
    }

    #[test]
    fn test_missing_backend_returns_clear_error() {
        let runner = MockCommandRunner {
            executed: Mutex::new(Vec::new()),
            handler: Box::new(|_cmd, _args| {
                Ok(CommandResult {
                    success: false,
                    stdout: String::new(),
                    stderr: "command not found".to_string(),
                })
            }),
        };

        let res = NetworkFirewall::activate_emergency_killswitch_with(
            &runner,
            FirewallBackend::Unavailable,
        );
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("No supported firewall backend"));
    }

    #[test]
    fn test_block_and_unblock_ip_in_dedicated_chain() {
        let delete_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dc = delete_count.clone();
        let runner = MockCommandRunner {
            executed: Mutex::new(Vec::new()),
            handler: Box::new(move |_cmd, args| {
                if args.contains(&"-N") {
                    Ok(CommandResult {
                        success: true,
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                } else if args.contains(&"-C") {
                    // Not blocked yet
                    Ok(CommandResult {
                        success: false,
                        stdout: String::new(),
                        stderr: "No rule".to_string(),
                    })
                } else if args.contains(&"-A") || args.contains(&"-I") {
                    Ok(CommandResult {
                        success: true,
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                } else if args.contains(&"-D") {
                    // Simulates 1 successful deletion
                    if dc.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                        Ok(CommandResult {
                            success: true,
                            stdout: String::new(),
                            stderr: String::new(),
                        })
                    } else {
                        Ok(CommandResult {
                            success: false,
                            stdout: String::new(),
                            stderr: "No rule".to_string(),
                        })
                    }
                } else {
                    Ok(CommandResult {
                        success: true,
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                }
            }),
        };

        let block_res = NetworkFirewall::block_ip_with(&runner, "203.0.113.5");
        assert!(block_res.is_ok());
        {
            let executed = runner.executed.lock().unwrap();
            assert!(executed
                .iter()
                .any(|c| c.contains("iptables -A NETSCOPE_BLOCK -d 203.0.113.5 -j DROP")));
        }

        let unblock_res = NetworkFirewall::unblock_ip_with(&runner, "203.0.113.5");
        assert!(unblock_res.is_ok());
    }

    #[test]
    fn test_unrelated_rules_preserved_during_deactivation() {
        let runner = MockCommandRunner {
            executed: Mutex::new(Vec::new()),
            handler: Box::new(|_cmd, args| {
                // If checking inactive status
                if args.contains(&"-C") {
                    Ok(CommandResult {
                        success: false,
                        stdout: String::new(),
                        stderr: "No rule".to_string(),
                    })
                } else {
                    Ok(CommandResult {
                        success: true,
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                }
            }),
        };

        let res = NetworkFirewall::deactivate_emergency_killswitch_with(
            &runner,
            FirewallBackend::Iptables,
        );
        assert!(res.is_ok());

        let executed = runner.executed.lock().unwrap();
        // Crucial safety check: ensure -F or -D is NEVER executed against bare INPUT or OUTPUT chains
        for cmd in executed.iter() {
            assert!(!cmd.contains("iptables -F INPUT"));
            assert!(!cmd.contains("iptables -F OUTPUT"));
            assert!(!cmd.contains("ip6tables -F INPUT"));
            assert!(!cmd.contains("ip6tables -F OUTPUT"));
        }
    }
}
