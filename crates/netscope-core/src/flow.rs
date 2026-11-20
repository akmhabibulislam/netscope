use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlowProtocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl std::fmt::Display for FlowProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Icmp => write!(f, "ICMP"),
            Self::Other(p) => write!(f, "PROTO-{}", p),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowState {
    New,
    Established,
    Closing,
    Closed,
    Timeout,
}

impl std::fmt::Display for FlowState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::New => write!(f, "New"),
            Self::Established => write!(f, "Established"),
            Self::Closing => write!(f, "Closing"),
            Self::Closed => write!(f, "Closed"),
            Self::Timeout => write!(f, "Timeout"),
        }
    }
}

/// Normalized Canonical Flow Key ensuring packets in either direction match the same conversation
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalFlowKey {
    pub endpoint_a: (IpAddr, u16),
    pub endpoint_b: (IpAddr, u16),
    pub protocol: FlowProtocol,
}

impl CanonicalFlowKey {
    pub fn new(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: FlowProtocol,
    ) -> (Self, bool) {
        let ep1 = (src_ip, src_port);
        let ep2 = (dst_ip, dst_port);

        // Deterministic ordering: compare IP then port
        let is_forward = match ep1.0.cmp(&ep2.0) {
            Ordering::Less => true,
            Ordering::Greater => false,
            Ordering::Equal => ep1.1 <= ep2.1,
        };

        if is_forward {
            (
                Self {
                    endpoint_a: ep1,
                    endpoint_b: ep2,
                    protocol,
                },
                true,
            )
        } else {
            (
                Self {
                    endpoint_a: ep2,
                    endpoint_b: ep1,
                    protocol,
                },
                false,
            )
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFlow {
    pub key: CanonicalFlowKey,
    pub start_time: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
    pub packets_a_to_b: u64,
    pub packets_b_to_a: u64,
    pub state: FlowState,
}

impl NetworkFlow {
    pub fn new(key: CanonicalFlowKey, bytes: usize, is_forward: bool) -> Self {
        let now = Utc::now();
        Self {
            key,
            start_time: now,
            last_seen: now,
            bytes_a_to_b: if is_forward { bytes as u64 } else { 0 },
            bytes_b_to_a: if !is_forward { bytes as u64 } else { 0 },
            packets_a_to_b: if is_forward { 1 } else { 0 },
            packets_b_to_a: if !is_forward { 1 } else { 0 },
            state: FlowState::New,
        }
    }

    pub fn update(&mut self, bytes: usize, is_forward: bool, tcp_flags: Option<u8>) {
        self.last_seen = Utc::now();
        if is_forward {
            self.packets_a_to_b += 1;
            self.bytes_a_to_b += bytes as u64;
        } else {
            self.packets_b_to_a += 1;
            self.bytes_b_to_a += bytes as u64;
        }

        if let Some(flags) = tcp_flags {
            // TCP Flag handling: SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04
            if flags & 0x04 != 0 {
                self.state = FlowState::Closed;
            } else if flags & 0x01 != 0 {
                self.state = FlowState::Closing;
            } else if (flags & 0x12) == 0x12 || (self.packets_a_to_b > 1 && self.packets_b_to_a > 1)
            {
                self.state = FlowState::Established;
            }
        } else if self.packets_a_to_b > 0 && self.packets_b_to_a > 0 {
            self.state = FlowState::Established;
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_a_to_b + self.bytes_b_to_a
    }

    pub fn total_packets(&self) -> u64 {
        self.packets_a_to_b + self.packets_b_to_a
    }

    pub fn duration_seconds(&self) -> i64 {
        (self.last_seen - self.start_time).num_seconds().max(1)
    }
}

pub struct FlowTracker {
    flows: HashMap<CanonicalFlowKey, NetworkFlow>,
    max_flows: usize,
    tcp_timeout_secs: i64,
    udp_timeout_secs: i64,
}

impl FlowTracker {
    pub fn new(max_flows: usize) -> Self {
        Self {
            flows: HashMap::new(),
            max_flows,
            tcp_timeout_secs: 300,
            udp_timeout_secs: 60,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_packet(
        &mut self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: FlowProtocol,
        length_bytes: usize,
        tcp_flags: Option<u8>,
    ) {
        let (key, is_forward) = CanonicalFlowKey::new(src_ip, src_port, dst_ip, dst_port, protocol);

        if let Some(flow) = self.flows.get_mut(&key) {
            flow.update(length_bytes, is_forward, tcp_flags);
        } else {
            if self.flows.len() >= self.max_flows {
                self.cleanup_expired();
                if self.flows.len() >= self.max_flows {
                    // Evict oldest flow
                    if let Some(oldest_key) = self
                        .flows
                        .iter()
                        .min_by_key(|(_, f)| f.last_seen)
                        .map(|(k, _)| k.clone())
                    {
                        self.flows.remove(&oldest_key);
                    }
                }
            }
            self.flows
                .insert(key.clone(), NetworkFlow::new(key, length_bytes, is_forward));
        }
    }

    pub fn cleanup_expired(&mut self) -> usize {
        let now = Utc::now();
        let tcp_timeout = self.tcp_timeout_secs;
        let udp_timeout = self.udp_timeout_secs;

        let before = self.flows.len();
        self.flows.retain(|_, flow| {
            let age = (now - flow.last_seen).num_seconds();
            match flow.key.protocol {
                FlowProtocol::Tcp => {
                    if flow.state == FlowState::Closed {
                        age < 15
                    } else {
                        age < tcp_timeout
                    }
                }
                FlowProtocol::Udp => age < udp_timeout,
                _ => age < 60,
            }
        });
        before - self.flows.len()
    }

    pub fn active_flows(&self) -> Vec<NetworkFlow> {
        let mut list: Vec<_> = self.flows.values().cloned().collect();
        list.sort_by_key(|a| std::cmp::Reverse(a.last_seen));
        list
    }

    pub fn count(&self) -> usize {
        self.flows.len()
    }
}

impl Default for FlowTracker {
    fn default() -> Self {
        Self::new(10000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_canonical_flow_symmetry() {
        let ip_a = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let ip_b = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        let (key1, fwd1) = CanonicalFlowKey::new(ip_a, 50000, ip_b, 443, FlowProtocol::Tcp);
        let (key2, fwd2) = CanonicalFlowKey::new(ip_b, 443, ip_a, 50000, FlowProtocol::Tcp);

        assert_eq!(key1, key2);
        assert_ne!(fwd1, fwd2);
    }

    #[test]
    fn test_flow_tracker_bidirectional_aggregation() {
        let mut tracker = FlowTracker::new(100);
        let ip_client = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
        let ip_server = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

        // SYN from client
        tracker.process_packet(
            ip_client,
            40000,
            ip_server,
            80,
            FlowProtocol::Tcp,
            60,
            Some(0x02),
        );
        assert_eq!(tracker.count(), 1);

        // SYN-ACK from server
        tracker.process_packet(
            ip_server,
            80,
            ip_client,
            40000,
            FlowProtocol::Tcp,
            60,
            Some(0x12),
        );
        assert_eq!(tracker.count(), 1);

        let flows = tracker.active_flows();
        assert_eq!(flows.len(), 1);
        let flow = &flows[0];
        assert_eq!(flow.total_packets(), 2);
        assert_eq!(flow.total_bytes(), 120);
        assert_eq!(flow.state, FlowState::Established);
    }
}
