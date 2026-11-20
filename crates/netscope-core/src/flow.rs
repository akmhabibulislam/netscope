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
    SynSent,
    SynAckReceived,
    Established,
    Closing,
    Closed,
    Reset,
    Timeout,
}

impl std::fmt::Display for FlowState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::New => write!(f, "New"),
            Self::SynSent => write!(f, "SYN-Sent"),
            Self::SynAckReceived => write!(f, "SYN-ACK-Received"),
            Self::Established => write!(f, "Established"),
            Self::Closing => write!(f, "Closing"),
            Self::Closed => write!(f, "Closed"),
            Self::Reset => write!(f, "Reset"),
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
    pub syn_from_a: bool,
    pub syn_from_b: bool,
    pub fin_from_a: bool,
    pub fin_from_b: bool,
}

impl NetworkFlow {
    pub fn new(
        key: CanonicalFlowKey,
        bytes: usize,
        is_forward: bool,
        tcp_flags: Option<u8>,
        now: DateTime<Utc>,
    ) -> Self {
        let mut flow = Self {
            key,
            start_time: now,
            last_seen: now,
            bytes_a_to_b: if is_forward { bytes as u64 } else { 0 },
            bytes_b_to_a: if !is_forward { bytes as u64 } else { 0 },
            packets_a_to_b: if is_forward { 1 } else { 0 },
            packets_b_to_a: if !is_forward { 1 } else { 0 },
            state: FlowState::New,
            syn_from_a: false,
            syn_from_b: false,
            fin_from_a: false,
            fin_from_b: false,
        };

        if flow.key.protocol == FlowProtocol::Tcp {
            if let Some(flags) = tcp_flags {
                if flags & 0x04 != 0 {
                    // RST
                    flow.state = FlowState::Reset;
                } else if (flags & 0x02) != 0 && (flags & 0x10) == 0 {
                    // Client SYN
                    if is_forward {
                        flow.syn_from_a = true;
                    } else {
                        flow.syn_from_b = true;
                    }
                    flow.state = FlowState::SynSent;
                }
            }
        }

        flow
    }

    pub fn update(
        &mut self,
        bytes: usize,
        is_forward: bool,
        tcp_flags: Option<u8>,
        now: DateTime<Utc>,
    ) {
        self.last_seen = now;
        if is_forward {
            self.packets_a_to_b += 1;
            self.bytes_a_to_b += bytes as u64;
        } else {
            self.packets_b_to_a += 1;
            self.bytes_b_to_a += bytes as u64;
        }

        if self.key.protocol == FlowProtocol::Tcp {
            if let Some(flags) = tcp_flags {
                let is_fin = (flags & 0x01) != 0;
                let is_syn = (flags & 0x02) != 0;
                let is_rst = (flags & 0x04) != 0;
                let is_ack = (flags & 0x10) != 0;

                if is_rst {
                    self.state = FlowState::Reset;
                } else if is_fin {
                    if is_forward {
                        self.fin_from_a = true;
                    } else {
                        self.fin_from_b = true;
                    }
                    if self.fin_from_a && self.fin_from_b {
                        self.state = FlowState::Closed;
                    } else {
                        self.state = FlowState::Closing;
                    }
                } else if is_syn {
                    if is_ack {
                        // SYN-ACK (Server response)
                        if is_forward {
                            self.syn_from_a = true;
                        } else {
                            self.syn_from_b = true;
                        }
                        if self.state == FlowState::SynSent || self.state == FlowState::New {
                            self.state = FlowState::SynAckReceived;
                        }
                    } else {
                        // Retransmitted or new SYN
                        if is_forward {
                            self.syn_from_a = true;
                        } else {
                            self.syn_from_b = true;
                        }
                        if self.state == FlowState::New {
                            self.state = FlowState::SynSent;
                        }
                    }
                } else if is_ack {
                    if self.state == FlowState::SynAckReceived {
                        // Handshake completion (Client sends ACK back to server)
                        let is_client_ack = if self.syn_from_a && !self.syn_from_b {
                            is_forward
                        } else if self.syn_from_b && !self.syn_from_a {
                            !is_forward
                        } else {
                            true
                        };
                        if is_client_ack {
                            self.state = FlowState::Established;
                        }
                    } else if self.state == FlowState::Closing {
                        if (is_forward && self.fin_from_b) || (!is_forward && self.fin_from_a) {
                            self.state = FlowState::Closed;
                        }
                    } else if self.state == FlowState::New
                        && self.packets_a_to_b >= 1
                        && self.packets_b_to_a >= 1
                    {
                        // Mid-stream pickup: established connection observed without initial handshake
                        self.state = FlowState::Established;
                    }
                }
            }
        } else if self.packets_a_to_b >= 1 && self.packets_b_to_a >= 1 {
            // UDP or ICMP bidirectional traffic
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
        self.process_packet_with_time(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol,
            length_bytes,
            tcp_flags,
            Utc::now(),
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_packet_with_time(
        &mut self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: FlowProtocol,
        length_bytes: usize,
        tcp_flags: Option<u8>,
        now: DateTime<Utc>,
    ) {
        if self.max_flows == 0 {
            return; // Capacity limit of zero enforced
        }

        let (key, is_forward) = CanonicalFlowKey::new(src_ip, src_port, dst_ip, dst_port, protocol);

        if let Some(flow) = self.flows.get_mut(&key) {
            flow.update(length_bytes, is_forward, tcp_flags, now);
        } else {
            if self.flows.len() >= self.max_flows {
                self.cleanup_expired_at(now);
                if self.flows.len() >= self.max_flows {
                    // Predictable LRU eviction: evict oldest flow
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
            self.flows.insert(
                key.clone(),
                NetworkFlow::new(key, length_bytes, is_forward, tcp_flags, now),
            );
        }
    }

    pub fn cleanup_expired(&mut self) -> usize {
        self.cleanup_expired_at(Utc::now())
    }

    pub fn cleanup_expired_at(&mut self, now: DateTime<Utc>) -> usize {
        let tcp_timeout = self.tcp_timeout_secs;
        let udp_timeout = self.udp_timeout_secs;

        let before = self.flows.len();
        self.flows.retain(|_, flow| {
            let age = (now - flow.last_seen).num_seconds();
            match flow.key.protocol {
                FlowProtocol::Tcp => {
                    if flow.state == FlowState::Closed || flow.state == FlowState::Reset {
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

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_canonical_flow_symmetry() {
        let ip_a = IpAddr::from_str("192.168.1.100").unwrap();
        let ip_b = IpAddr::from_str("142.250.190.46").unwrap();

        let (key1, fwd1) = CanonicalFlowKey::new(ip_a, 50000, ip_b, 443, FlowProtocol::Tcp);
        let (key2, fwd2) = CanonicalFlowKey::new(ip_b, 443, ip_a, 50000, FlowProtocol::Tcp);

        assert_eq!(key1, key2);
        assert_ne!(fwd1, fwd2);
    }

    #[test]
    fn test_tcp_three_way_handshake_state_machine() {
        let ip_client = IpAddr::from_str("192.168.1.50").unwrap();
        let ip_server = IpAddr::from_str("93.184.216.34").unwrap();
        let mut tracker = FlowTracker::new(100);
        let now = Utc::now();

        // 1. Client sends SYN (0x02)
        tracker.process_packet_with_time(
            ip_client,
            49152,
            ip_server,
            80,
            FlowProtocol::Tcp,
            60,
            Some(0x02),
            now,
        );
        let flows = tracker.active_flows();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].state, FlowState::SynSent);
        assert_eq!(flows[0].packets_a_to_b + flows[0].packets_b_to_a, 1);

        // 2. Server responds with SYN-ACK (0x12)
        tracker.process_packet_with_time(
            ip_server,
            80,
            ip_client,
            49152,
            FlowProtocol::Tcp,
            60,
            Some(0x12),
            now,
        );
        let flows = tracker.active_flows();
        // MUST NOT be Established after 2 packets!
        assert_eq!(flows[0].state, FlowState::SynAckReceived);
        assert_eq!(flows[0].packets_a_to_b + flows[0].packets_b_to_a, 2);

        // 3. Client sends ACK (0x10) to finalize handshake
        tracker.process_packet_with_time(
            ip_client,
            49152,
            ip_server,
            80,
            FlowProtocol::Tcp,
            52,
            Some(0x10),
            now,
        );
        let flows = tracker.active_flows();
        assert_eq!(flows[0].state, FlowState::Established);
        assert_eq!(flows[0].packets_a_to_b + flows[0].packets_b_to_a, 3);
    }

    #[test]
    fn test_tcp_reset_transitions_to_reset() {
        let ip_a = IpAddr::from_str("10.0.0.1").unwrap();
        let ip_b = IpAddr::from_str("10.0.0.2").unwrap();
        let mut tracker = FlowTracker::new(10);
        let now = Utc::now();

        tracker.process_packet_with_time(
            ip_a,
            1234,
            ip_b,
            80,
            FlowProtocol::Tcp,
            60,
            Some(0x02),
            now,
        );
        tracker.process_packet_with_time(
            ip_b,
            80,
            ip_a,
            1234,
            FlowProtocol::Tcp,
            60,
            Some(0x04),
            now,
        ); // RST

        let flows = tracker.active_flows();
        assert_eq!(flows[0].state, FlowState::Reset);
    }

    #[test]
    fn test_tcp_fin_teardown_transitions_to_closing_and_closed() {
        let ip_a = IpAddr::from_str("10.0.0.1").unwrap();
        let ip_b = IpAddr::from_str("10.0.0.2").unwrap();
        let mut tracker = FlowTracker::new(10);
        let now = Utc::now();

        // 3-way handshake
        tracker.process_packet_with_time(
            ip_a,
            1234,
            ip_b,
            80,
            FlowProtocol::Tcp,
            60,
            Some(0x02),
            now,
        );
        tracker.process_packet_with_time(
            ip_b,
            80,
            ip_a,
            1234,
            FlowProtocol::Tcp,
            60,
            Some(0x12),
            now,
        );
        tracker.process_packet_with_time(
            ip_a,
            1234,
            ip_b,
            80,
            FlowProtocol::Tcp,
            52,
            Some(0x10),
            now,
        );
        assert_eq!(tracker.active_flows()[0].state, FlowState::Established);

        // Client FIN (0x01)
        tracker.process_packet_with_time(
            ip_a,
            1234,
            ip_b,
            80,
            FlowProtocol::Tcp,
            52,
            Some(0x01),
            now,
        );
        assert_eq!(tracker.active_flows()[0].state, FlowState::Closing);

        // Server FIN (0x01)
        tracker.process_packet_with_time(
            ip_b,
            80,
            ip_a,
            1234,
            FlowProtocol::Tcp,
            52,
            Some(0x01),
            now,
        );
        assert_eq!(tracker.active_flows()[0].state, FlowState::Closed);
    }

    #[test]
    fn test_max_flows_zero_enforced() {
        let ip_a = IpAddr::from_str("10.0.0.1").unwrap();
        let ip_b = IpAddr::from_str("10.0.0.2").unwrap();
        let mut tracker = FlowTracker::new(0);

        tracker.process_packet(ip_a, 1234, ip_b, 80, FlowProtocol::Tcp, 60, Some(0x02));
        assert_eq!(tracker.len(), 0);
    }

    #[test]
    fn test_predictable_lru_eviction() {
        let ip_a = IpAddr::from_str("10.0.0.1").unwrap();
        let ip_b = IpAddr::from_str("10.0.0.2").unwrap();
        let mut tracker = FlowTracker::new(2);
        let t0 = Utc::now();
        let t1 = t0 + chrono::Duration::seconds(5);
        let t2 = t0 + chrono::Duration::seconds(10);

        tracker.process_packet_with_time(ip_a, 1001, ip_b, 80, FlowProtocol::Udp, 50, None, t0);
        tracker.process_packet_with_time(ip_a, 1002, ip_b, 80, FlowProtocol::Udp, 50, None, t1);
        assert_eq!(tracker.len(), 2);

        // Third flow arrives at t2: oldest flow (port 1001) should be evicted
        tracker.process_packet_with_time(ip_a, 1003, ip_b, 80, FlowProtocol::Udp, 50, None, t2);
        assert_eq!(tracker.len(), 2);

        let flows = tracker.active_flows();
        let ports: Vec<u16> = flows.iter().map(|f| f.key.endpoint_a.1).collect();
        assert!(!ports.contains(&1001));
        assert!(ports.contains(&1002));
        assert!(ports.contains(&1003));
    }
}
