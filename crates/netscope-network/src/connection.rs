use chrono::Utc;
use netscope_core::{ConnectionState, NetworkConnection, Protocol};
use netscope_process::ProcessResolver;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use tracing::warn;

pub struct ConnectionScanner {
    process_resolver: ProcessResolver,
}

impl ConnectionScanner {
    pub fn new() -> Self {
        let mut resolver = ProcessResolver::new();
        let _ = resolver.refresh();
        Self {
            process_resolver: resolver,
        }
    }

    pub fn scan_connections(&mut self) -> Vec<NetworkConnection> {
        let _ = self.process_resolver.refresh();
        let mut connections = Vec::new();

        // Scan TCP IPv4
        connections.extend(self.parse_proc_net_tcp("/proc/net/tcp", Protocol::Tcp, false));
        // Scan TCP IPv6
        connections.extend(self.parse_proc_net_tcp("/proc/net/tcp6", Protocol::Tcp, true));
        // Scan UDP IPv4
        connections.extend(self.parse_proc_net_udp("/proc/net/udp", Protocol::Udp, false));
        // Scan UDP IPv6
        connections.extend(self.parse_proc_net_udp("/proc/net/udp6", Protocol::Udp, true));

        connections
    }

    fn parse_proc_net_tcp(&self, path_str: &str, protocol: Protocol, is_ipv6: bool) -> Vec<NetworkConnection> {
        let path = Path::new(path_str);
        if !path.exists() {
            return Vec::new();
        }

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to read {}: {}", path_str, e);
                return Vec::new();
            }
        };

        let mut results = Vec::new();
        let now = Utc::now();

        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }

            let local_socket = fields[1];
            let remote_socket = fields[2];
            let state_hex = fields[3];
            let inode_str = fields[9];

            let (local_addr, local_port) = match Self::parse_socket_address(local_socket, is_ipv6) {
                Some(res) => res,
                None => continue,
            };

            let (remote_addr, remote_port) = match Self::parse_socket_address(remote_socket, is_ipv6) {
                Some(res) => res,
                None => continue,
            };

            let state_val = u8::from_str_radix(state_hex, 16).unwrap_or(0);
            let state = match state_val {
                1 => ConnectionState::Established,
                2 => ConnectionState::SynSent,
                3 => ConnectionState::SynRecv,
                4 => ConnectionState::FinWait1,
                5 => ConnectionState::FinWait2,
                6 => ConnectionState::TimeWait,
                7 => ConnectionState::Closed,
                8 => ConnectionState::CloseWait,
                9 => ConnectionState::LastAck,
                10 => ConnectionState::Listen,
                11 => ConnectionState::Closing,
                other => ConnectionState::Unknown(other),
            };

            let inode = inode_str.parse::<u64>().unwrap_or(0);
            let process = self.process_resolver.get_process_by_inode(inode);

            let id = format!("{}:{}-{}:{}-{}", protocol, local_addr, local_port, remote_addr, remote_port);

            results.push(NetworkConnection {
                id,
                protocol,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state,
                inode,
                process,
                reverse_dns: None,
                country: None,
                city: None,
                asn: None,
                first_seen: now,
                last_seen: now,
            });
        }

        results
    }

    fn parse_proc_net_udp(&self, path_str: &str, protocol: Protocol, is_ipv6: bool) -> Vec<NetworkConnection> {
        let path = Path::new(path_str);
        if !path.exists() {
            return Vec::new();
        }

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to read {}: {}", path_str, e);
                return Vec::new();
            }
        };

        let mut results = Vec::new();
        let now = Utc::now();

        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }

            let local_socket = fields[1];
            let remote_socket = fields[2];
            let inode_str = fields[9];

            let (local_addr, local_port) = match Self::parse_socket_address(local_socket, is_ipv6) {
                Some(res) => res,
                None => continue,
            };

            let (remote_addr, remote_port) = match Self::parse_socket_address(remote_socket, is_ipv6) {
                Some(res) => res,
                None => continue,
            };

            let inode = inode_str.parse::<u64>().unwrap_or(0);
            let process = self.process_resolver.get_process_by_inode(inode);

            let state = if remote_port == 0 {
                ConnectionState::Listen
            } else {
                ConnectionState::Connected
            };

            let id = format!("{}:{}-{}:{}-{}", protocol, local_addr, local_port, remote_addr, remote_port);

            results.push(NetworkConnection {
                id,
                protocol,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state,
                inode,
                process,
                reverse_dns: None,
                country: None,
                city: None,
                asn: None,
                first_seen: now,
                last_seen: now,
            });
        }

        results
    }

    fn parse_socket_address(s: &str, is_ipv6: bool) -> Option<(IpAddr, u16)> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return None;
        }

        let ip_hex = parts[0];
        let port_hex = parts[1];

        let port = u16::from_str_radix(port_hex, 16).ok()?;

        if is_ipv6 {
            if ip_hex.len() != 32 {
                return None;
            }
            // IPv6 addresses in /proc/net are represented as 4 little-endian 32-bit words
            let mut words = [0u32; 4];
            for i in 0..4 {
                words[i] = u32::from_str_radix(&ip_hex[i * 8..(i + 1) * 8], 16).ok()?;
            }

            let mut octets = [0u8; 16];
            for (i, word) in words.iter().enumerate() {
                let bytes = word.to_ne_bytes();
                octets[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
            }
            Some((IpAddr::V6(Ipv6Addr::from(octets)), port))
        } else {
            if ip_hex.len() != 8 {
                return None;
            }
            let ip_num = u32::from_str_radix(ip_hex, 16).ok()?;
            // IPv4 is little-endian in Linux /proc/net/tcp
            let octets = ip_num.to_ne_bytes();
            Some((IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
    }
}

impl Default for ConnectionScanner {
    fn default() -> Self {
        Self::new()
    }
}
