use chrono::Utc;
use netscope_core::{CapturedPacketSummary, PacketDirection};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureState {
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
}

impl std::fmt::Display for CaptureState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stopped => write!(f, "Stopped"),
            Self::Starting => write!(f, "Starting"),
            Self::Running => write!(f, "Running"),
            Self::Stopping => write!(f, "Stopping"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

pub struct LiveTrafficSniffer {
    state: Arc<Mutex<CaptureState>>,
    has_raw_permission: Arc<Mutex<bool>>,
    last_error: Arc<Mutex<Option<String>>>,
    packet_counter: Arc<AtomicU64>,
    captured_packets: Arc<Mutex<VecDeque<CapturedPacketSummary>>>,
    local_ips: Arc<Mutex<Vec<IpAddr>>>,
    worker_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    stop_signal: Arc<Mutex<Option<mpsc::Sender<()>>>>,
}

impl Clone for LiveTrafficSniffer {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            has_raw_permission: self.has_raw_permission.clone(),
            last_error: self.last_error.clone(),
            packet_counter: self.packet_counter.clone(),
            captured_packets: self.captured_packets.clone(),
            local_ips: self.local_ips.clone(),
            worker_handle: self.worker_handle.clone(),
            stop_signal: self.stop_signal.clone(),
        }
    }
}

impl LiveTrafficSniffer {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(CaptureState::Stopped)),
            has_raw_permission: Arc::new(Mutex::new(false)),
            last_error: Arc::new(Mutex::new(None)),
            packet_counter: Arc::new(AtomicU64::new(0)),
            captured_packets: Arc::new(Mutex::new(VecDeque::with_capacity(5000))),
            local_ips: Arc::new(Mutex::new(Vec::new())),
            worker_handle: Arc::new(Mutex::new(None)),
            stop_signal: Arc::new(Mutex::new(None)),
        }
    }

    pub fn set_local_ips(&self, ips: Vec<IpAddr>) {
        if let Ok(mut l) = self.local_ips.lock() {
            *l = ips;
        }
    }

    pub fn state(&self) -> CaptureState {
        self.state.lock().map(|s| *s).unwrap_or(CaptureState::Stopped)
    }

    pub fn is_running(&self) -> bool {
        self.state() == CaptureState::Running
    }

    pub fn has_raw_permission(&self) -> bool {
        self.has_raw_permission.lock().map(|p| *p).unwrap_or(false)
    }

    pub fn get_last_error(&self) -> Option<String> {
        self.last_error.lock().ok().and_then(|e| e.clone())
    }

    /// Synchronously attempts to start managed capture worker.
    /// Returns Ok(()) ONLY after socket creation and binding succeed.
    /// If an interface name is specified, properly resolves its ifindex and binds with sockaddr_ll!
    pub fn start_capture(&self) -> Result<(), String> {
        self.start_capture_on(None)
    }

    pub fn start_capture_on(&self, interface: Option<&str>) -> Result<(), String> {
        let mut state_guard = self.state.lock().map_err(|e| e.to_string())?;
        if *state_guard == CaptureState::Running || *state_guard == CaptureState::Starting {
            return Ok(()); // Already running
        }

        *state_guard = CaptureState::Starting;
        if let Ok(mut err) = self.last_error.lock() {
            *err = None;
        }

        // 1. Attempt raw socket creation directly in calling thread first to guarantee synchronous error feedback
        let socket_fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            )
        };

        if socket_fd < 0 {
            let err_msg = "AF_PACKET raw socket permission denied: CAP_NET_RAW capability required.".to_string();
            if let Ok(mut p) = self.has_raw_permission.lock() {
                *p = false;
            }
            if let Ok(mut err) = self.last_error.lock() {
                *err = Some(err_msg.clone());
            }
            *state_guard = CaptureState::Failed;
            warn!("{}", err_msg);
            return Err(err_msg);
        }

        if let Ok(mut p) = self.has_raw_permission.lock() {
            *p = true;
        }

        // 2. Interface Binding: if an interface is specified, bind directly using libc::sockaddr_ll
        if let Some(if_name) = interface {
            let c_ifname = std::ffi::CString::new(if_name).map_err(|e| e.to_string())?;
            let ifindex = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) };
            if ifindex == 0 {
                unsafe { libc::close(socket_fd) };
                let err_msg = format!("Interface '{}' not found or invalid ifindex", if_name);
                *state_guard = CaptureState::Failed;
                return Err(err_msg);
            }

            let mut bind_addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            bind_addr.sll_family = libc::AF_PACKET as u16;
            bind_addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
            bind_addr.sll_ifindex = ifindex as i32;

            let bind_res = unsafe {
                libc::bind(
                    socket_fd,
                    &bind_addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };

            if bind_res < 0 {
                unsafe { libc::close(socket_fd) };
                let err_msg = format!("Failed to bind AF_PACKET to interface '{}' (errno: {})", if_name, unsafe { *libc::__errno_location() });
                *state_guard = CaptureState::Failed;
                return Err(err_msg);
            }
            info!("Bound live packet socket to interface '{}' (ifindex: {})", if_name, ifindex);
        }

        // Configure socket timeout: 250ms
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 250_000,
        };
        let sockopt_res = unsafe {
            libc::setsockopt(
                socket_fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            )
        };
        if sockopt_res < 0 {
            unsafe { libc::close(socket_fd) };
            let err_msg = "Failed to configure SO_RCVTIMEO on packet socket".to_string();
            *state_guard = CaptureState::Failed;
            return Err(err_msg);
        }

        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        if let Ok(mut s) = self.stop_signal.lock() {
            *s = Some(stop_tx);
        }

        let state_arc = self.state.clone();
        let counter_arc = self.packet_counter.clone();
        let buffer_arc = self.captured_packets.clone();
        let local_ips_arc = self.local_ips.clone();

        *state_guard = CaptureState::Running;

        let handle = std::thread::spawn(move || {
            let mut raw_buffer = [0u8; 65535];

            loop {
                // Check stop signal non-blockingly
                if stop_rx.try_recv().is_ok() {
                    break;
                }

                let mut saddr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
                let mut saddr_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

                let n = unsafe {
                    libc::recvfrom(
                        socket_fd,
                        raw_buffer.as_mut_ptr() as *mut libc::c_void,
                        raw_buffer.len(),
                        0,
                        &mut saddr as *mut _ as *mut libc::sockaddr,
                        &mut saddr_len,
                    )
                };

                if n > 14 {
                    let packet_bytes = &raw_buffer[..n as usize];
                    // Extract packet type from Linux sockaddr_ll:
                    // PACKET_HOST = 0 (Incoming to local machine)
                    // PACKET_BROADCAST = 1
                    // PACKET_MULTICAST = 2
                    // PACKET_OTHERHOST = 3 (Promiscuous)
                    // PACKET_OUTGOING = 4 (Outgoing from local machine)
                    let pkttype = saddr.sll_pkttype;
                    let ifindex = saddr.sll_ifindex;

                    if let Some(packet) = Self::parse_ethernet_frame_with_meta(
                        packet_bytes,
                        pkttype,
                        ifindex,
                        &counter_arc,
                        &local_ips_arc,
                    ) {
                        if let Ok(mut q) = buffer_arc.lock() {
                            if q.len() >= 5000 {
                                q.pop_front();
                            }
                            q.push_back(packet);
                        }
                    }
                }
            }

            unsafe { libc::close(socket_fd) };
            if let Ok(mut st) = state_arc.lock() {
                *st = CaptureState::Stopped;
            }
            info!("Live packet sniffer worker joined and shut down cleanly");
        });

        if let Ok(mut w) = self.worker_handle.lock() {
            *w = Some(handle);
        }

        Ok(())
    }

    /// Stops capture worker and deterministically joins thread
    pub fn stop_capture(&self) {
        if let Ok(mut st) = self.state.lock() {
            if *st != CaptureState::Running && *st != CaptureState::Starting {
                return;
            }
            *st = CaptureState::Stopping;
        }

        if let Ok(mut s) = self.stop_signal.lock() {
            if let Some(tx) = s.take() {
                let _ = tx.send(());
            }
        }

        if let Ok(mut w) = self.worker_handle.lock() {
            if let Some(handle) = w.take() {
                let _ = handle.join();
            }
        }

        if let Ok(mut st) = self.state.lock() {
            *st = CaptureState::Stopped;
        }
    }

    pub fn get_recent_packets(&self, limit: usize) -> Vec<CapturedPacketSummary> {
        if let Ok(q) = self.captured_packets.lock() {
            q.iter().rev().take(limit).cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Comprehensive Ethernet frame parser supporting VLAN tags (802.1Q), IPv4 (with fragment offset check),
    /// IPv6 (with full Extension Header traversal), and Linux kernel sll_pkttype directional metadata.
    pub fn parse_ethernet_frame(
        bytes: &[u8],
        counter: &AtomicU64,
        local_ips_arc: &Arc<Mutex<Vec<IpAddr>>>,
    ) -> Option<CapturedPacketSummary> {
        Self::parse_ethernet_frame_with_meta(bytes, 0, 0, counter, local_ips_arc)
    }

    pub fn parse_ethernet_frame_with_meta(
        bytes: &[u8],
        sll_pkttype: u8,
        _ifindex: i32,
        counter: &AtomicU64,
        local_ips_arc: &Arc<Mutex<Vec<IpAddr>>>,
    ) -> Option<CapturedPacketSummary> {
        if bytes.len() < 14 {
            return None;
        }

        let mut offset = 12;
        let mut ether_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        offset += 2;

        // Handle 802.1Q VLAN Tagging (0x8100) and 802.1ad QinQ (0x88A8)
        while (ether_type == 0x8100 || ether_type == 0x88A8) && bytes.len() >= offset + 4 {
            offset += 2; // skip TCI / Priority & VID
            ether_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            offset += 2;
        }

        match ether_type {
            // IPv4 Frame
            0x0800 => Self::parse_ipv4(&bytes[offset..], bytes.len(), sll_pkttype, counter, local_ips_arc),
            // IPv6 Frame
            0x86DD => Self::parse_ipv6(&bytes[offset..], bytes.len(), sll_pkttype, counter, local_ips_arc),
            // ARP (0x0806)
            0x0806 => Self::parse_arp(&bytes[offset..], bytes.len(), counter),
            _ => None,
        }
    }

    fn parse_arp(
        arp_bytes: &[u8],
        total_frame_len: usize,
        counter: &AtomicU64,
    ) -> Option<CapturedPacketSummary> {
        if arp_bytes.len() < 28 {
            return None;
        }

        let op = u16::from_be_bytes([arp_bytes[6], arp_bytes[7]]);
        let op_name = match op {
            1 => "ARP Request",
            2 => "ARP Reply",
            _ => "ARP",
        };

        let src_ip = Ipv4Addr::new(arp_bytes[14], arp_bytes[15], arp_bytes[16], arp_bytes[17]);
        let dst_ip = Ipv4Addr::new(arp_bytes[24], arp_bytes[25], arp_bytes[26], arp_bytes[27]);

        let id = counter.fetch_add(1, Ordering::SeqCst);
        Some(CapturedPacketSummary {
            id,
            timestamp: Utc::now(),
            direction: PacketDirection::Inbound,
            protocol: "ARP".to_string(),
            src_addr: src_ip.to_string(),
            src_port: None,
            dst_addr: dst_ip.to_string(),
            dst_port: None,
            length_bytes: total_frame_len,
            summary: format!("{} (Who has {}? Tell {}) [{} bytes]", op_name, dst_ip, src_ip, total_frame_len),
        })
    }

    fn parse_ipv4(
        ip_bytes: &[u8],
        total_frame_len: usize,
        sll_pkttype: u8,
        counter: &AtomicU64,
        local_ips_arc: &Arc<Mutex<Vec<IpAddr>>>,
    ) -> Option<CapturedPacketSummary> {
        if ip_bytes.len() < 20 {
            return None;
        }

        let version = (ip_bytes[0] >> 4) & 0x0F;
        if version != 4 {
            return None;
        }

        let ihl = ((ip_bytes[0] & 0x0F) as usize) * 4;
        if ihl < 20 || ip_bytes.len() < ihl {
            return None;
        }

        // Strict IPv4 Total Length validation
        let total_length = u16::from_be_bytes([ip_bytes[2], ip_bytes[3]]) as usize;
        if total_length > ip_bytes.len() || total_length < ihl {
            return None; // Corrupted or truncated header length
        }

        // IPv4 Fragmentation handling
        let flags_frag = u16::from_be_bytes([ip_bytes[6], ip_bytes[7]]);
        let frag_offset = (flags_frag & 0x1FFF) * 8;
        let is_non_initial_fragment = frag_offset > 0;

        let protocol_num = ip_bytes[9];
        let src_ip = Ipv4Addr::new(ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]);
        let dst_ip = Ipv4Addr::new(ip_bytes[16], ip_bytes[17], ip_bytes[18], ip_bytes[19]);

        let payload = &ip_bytes[ihl..total_length];

        let (src_port, dst_port, proto_name, app_info) = if is_non_initial_fragment {
            (
                None,
                None,
                "IPv4-Frag",
                "IPv4 Non-Initial Fragment",
            )
        } else {
            match protocol_num {
                6 => {
                    // TCP (min header 20 bytes)
                    if payload.len() >= 20 {
                        let sp = u16::from_be_bytes([payload[0], payload[1]]);
                        let dp = u16::from_be_bytes([payload[2], payload[3]]);
                        let data_offset = ((payload[12] >> 4) as usize) * 4;
                        if data_offset < 20 || data_offset > payload.len() {
                            (Some(sp), Some(dp), "TCP", "TCP (Malformed Offset)")
                        } else {
                            let app = if sp == 443 || dp == 443 {
                                "TLS/HTTPS"
                            } else if sp == 80 || dp == 80 {
                                "HTTP"
                            } else if sp == 53 || dp == 53 {
                                "DNS-over-TCP"
                            } else if sp == 22 || dp == 22 {
                                "SSH"
                            } else {
                                "TCP"
                            };
                            (Some(sp), Some(dp), "TCP", app)
                        }
                    } else if payload.len() >= 4 {
                        let sp = u16::from_be_bytes([payload[0], payload[1]]);
                        let dp = u16::from_be_bytes([payload[2], payload[3]]);
                        (Some(sp), Some(dp), "TCP", "TCP (Truncated)")
                    } else {
                        (None, None, "TCP", "TCP")
                    }
                }
                17 => {
                    // UDP (Header 8 bytes)
                    if payload.len() >= 8 {
                        let sp = u16::from_be_bytes([payload[0], payload[1]]);
                        let dp = u16::from_be_bytes([payload[2], payload[3]]);
                        let udp_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
                        if udp_len < 8 || udp_len > payload.len() {
                            (Some(sp), Some(dp), "UDP", "UDP (Length Mismatch)")
                        } else {
                            let app = if sp == 53 || dp == 53 {
                                "DNS"
                            } else if sp == 67 || dp == 67 || sp == 68 || dp == 68 {
                                "DHCP"
                            } else if sp == 443 || dp == 443 {
                                "QUIC/HTTP3"
                            } else if sp == 123 || dp == 123 {
                                "NTP"
                            } else {
                                "UDP"
                            };
                            (Some(sp), Some(dp), "UDP", app)
                        }
                    } else if payload.len() >= 4 {
                        let sp = u16::from_be_bytes([payload[0], payload[1]]);
                        let dp = u16::from_be_bytes([payload[2], payload[3]]);
                        (Some(sp), Some(dp), "UDP", "UDP (Truncated)")
                    } else {
                        (None, None, "UDP", "UDP")
                    }
                }
                1 => {
                    // ICMP
                    let icmp_type = if !payload.is_empty() { payload[0] } else { 255 };
                    let desc = match icmp_type {
                        0 => "ICMP Echo Reply",
                        8 => "ICMP Echo Request",
                        3 => "ICMP Dest Unreachable",
                        11 => "ICMP Time Exceeded",
                        _ => "ICMP Control",
                    };
                    (None, None, "ICMP", desc)
                }
                50 => (None, None, "ESP", "IPsec Encapsulated Security Payload (Encrypted)"),
                51 => (None, None, "AH", "IPsec Authentication Header"),
                _ => (None, None, "IPv4", "Raw IPv4 Protocol"),
            }
        };

        // Direction classification: prioritize Linux kernel sll_pkttype
        let is_outbound = match sll_pkttype {
            4 => true,  // PACKET_OUTGOING
            0..=3 => false, // PACKET_HOST, BROADCAST, MULTICAST, OTHERHOST
            _ => {
                // Fallback to verified local interface IP matching
                if let Ok(ips) = local_ips_arc.lock() {
                    ips.contains(&IpAddr::V4(src_ip))
                } else {
                    false
                }
            }
        };

        let summary = format!(
            "{} {}:{} -> {}:{} [{} bytes]",
            app_info,
            src_ip,
            src_port.unwrap_or(0),
            dst_ip,
            dst_port.unwrap_or(0),
            total_frame_len
        );

        let id = counter.fetch_add(1, Ordering::SeqCst);
        Some(CapturedPacketSummary {
            id,
            timestamp: Utc::now(),
            direction: if is_outbound {
                PacketDirection::Outbound
            } else {
                PacketDirection::Inbound
            },
            protocol: proto_name.to_string(),
            src_addr: src_ip.to_string(),
            src_port,
            dst_addr: dst_ip.to_string(),
            dst_port,
            length_bytes: total_frame_len,
            summary,
        })
    }

    /// Parse IPv6 packet with full RFC 8200 Extension Header traversal
    fn parse_ipv6(
        ip_bytes: &[u8],
        total_frame_len: usize,
        sll_pkttype: u8,
        counter: &AtomicU64,
        local_ips_arc: &Arc<Mutex<Vec<IpAddr>>>,
    ) -> Option<CapturedPacketSummary> {
        if ip_bytes.len() < 40 {
            return None;
        }

        let version = (ip_bytes[0] >> 4) & 0x0F;
        if version != 6 {
            return None;
        }

        let payload_len = u16::from_be_bytes([ip_bytes[4], ip_bytes[5]]) as usize;
        if 40 + payload_len > ip_bytes.len() {
            return None; // Truncated IPv6 frame
        }

        let mut next_header = ip_bytes[6];
        let mut src_octets = [0u8; 16];
        src_octets.copy_from_slice(&ip_bytes[8..24]);
        let src_ip = Ipv6Addr::from(src_octets);

        let mut dst_octets = [0u8; 16];
        dst_octets.copy_from_slice(&ip_bytes[24..40]);
        let dst_ip = Ipv6Addr::from(dst_octets);

        let mut offset = 40;
        let mut is_non_initial_fragment = false;

        // Traverse IPv6 Extension Headers
        while offset < 40 + payload_len {
            match next_header {
                // Hop-by-Hop (0), Routing (43), Destination Options (60)
                0 | 43 | 60 => {
                    if offset + 2 > ip_bytes.len() {
                        break;
                    }
                    next_header = ip_bytes[offset];
                    let ext_len = ((ip_bytes[offset + 1] as usize) + 1) * 8;
                    offset += ext_len;
                }
                // Fragment Header (44)
                44 => {
                    if offset + 8 > ip_bytes.len() {
                        break;
                    }
                    next_header = ip_bytes[offset];
                    let frag_offset = u16::from_be_bytes([ip_bytes[offset + 2], ip_bytes[offset + 3]]) >> 3;
                    if frag_offset > 0 {
                        is_non_initial_fragment = true;
                    }
                    offset += 8;
                }
                // Authentication Header (51)
                51 => {
                    if offset + 2 > ip_bytes.len() {
                        break;
                    }
                    next_header = ip_bytes[offset];
                    let ah_len = ((ip_bytes[offset + 1] as usize) + 2) * 4;
                    offset += ah_len;
                }
                // Encapsulated Security Payload (50)
                50 => break,
                // Terminal Protocol
                _ => break,
            }
        }

        let payload = if offset <= ip_bytes.len() {
            &ip_bytes[offset..]
        } else {
            &[]
        };

        let (src_port, dst_port, proto_name, app_info) = if is_non_initial_fragment {
            (
                None,
                None,
                "IPv6-Frag",
                "IPv6 Fragment Continuation",
            )
        } else {
            match next_header {
                6 => {
                    // TCP
                    if payload.len() >= 4 {
                        let sp = u16::from_be_bytes([payload[0], payload[1]]);
                        let dp = u16::from_be_bytes([payload[2], payload[3]]);
                        let app = if sp == 443 || dp == 443 {
                            "TLS/HTTPS"
                        } else if sp == 80 || dp == 80 {
                            "HTTP"
                        } else if sp == 53 || dp == 53 {
                            "DNS"
                        } else {
                            "TCP"
                        };
                        (Some(sp), Some(dp), "TCP", app)
                    } else {
                        (None, None, "TCP", "TCP")
                    }
                }
                17 => {
                    // UDP
                    if payload.len() >= 4 {
                        let sp = u16::from_be_bytes([payload[0], payload[1]]);
                        let dp = u16::from_be_bytes([payload[2], payload[3]]);
                        let app = if sp == 53 || dp == 53 {
                            "DNS"
                        } else if sp == 443 || dp == 443 {
                            "QUIC"
                        } else {
                            "UDP"
                        };
                        (Some(sp), Some(dp), "UDP", app)
                    } else {
                        (None, None, "UDP", "UDP")
                    }
                }
                58 => (None, None, "ICMPv6", "ICMPv6 Control"),
                50 => (None, None, "ESP", "IPsec Encapsulated Security Payload (Encrypted)"),
                51 => (None, None, "AH", "IPsec Authentication Header"),
                _ => (None, None, "IPv6", "IPv6 NextHeader"),
            }
        };

        let is_outbound = match sll_pkttype {
            4 => true,
            0..=3 => false,
            _ => {
                if let Ok(ips) = local_ips_arc.lock() {
                    ips.contains(&IpAddr::V6(src_ip))
                } else {
                    false
                }
            }
        };

        let summary = format!(
            "{} [{}]:{} -> [{}]:{} [{} bytes]",
            app_info,
            src_ip,
            src_port.unwrap_or(0),
            dst_ip,
            dst_port.unwrap_or(0),
            total_frame_len
        );

        let id = counter.fetch_add(1, Ordering::SeqCst);
        Some(CapturedPacketSummary {
            id,
            timestamp: Utc::now(),
            direction: if is_outbound {
                PacketDirection::Outbound
            } else {
                PacketDirection::Inbound
            },
            protocol: proto_name.to_string(),
            src_addr: src_ip.to_string(),
            src_port,
            dst_addr: dst_ip.to_string(),
            dst_port,
            length_bytes: total_frame_len,
            summary,
        })
    }
}

impl Default for LiveTrafficSniffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_arp_frame() {
        let mut frame = vec![0u8; 42];
        frame[12] = 0x08;
        frame[13] = 0x06; // EtherType = ARP
        frame[14 + 6] = 0x00;
        frame[14 + 7] = 0x01; // Opcode = 1 (Request)
        // Sender IP: 192.168.1.1
        frame[14 + 14] = 192;
        frame[14 + 15] = 168;
        frame[14 + 16] = 1;
        frame[14 + 17] = 1;
        // Target IP: 192.168.1.254
        frame[14 + 24] = 192;
        frame[14 + 25] = 168;
        frame[14 + 26] = 1;
        frame[14 + 27] = 254;

        let counter = AtomicU64::new(0);
        let local_ips = Arc::new(Mutex::new(vec![]));
        let packet = LiveTrafficSniffer::parse_ethernet_frame(&frame, &counter, &local_ips)
            .expect("Must parse ARP");

        assert_eq!(packet.protocol, "ARP");
        assert_eq!(packet.src_addr, "192.168.1.1");
        assert_eq!(packet.dst_addr, "192.168.1.254");
    }

    #[test]
    fn test_parse_valid_ipv4_tcp_frame() {
        let mut frame = vec![0u8; 54];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[14] = 0x45; // IPv4, IHL 5
        frame[16] = 0x00;
        frame[17] = 40;   // Total length = 40
        frame[23] = 6;    // TCP
        frame[26] = 192;
        frame[27] = 168;
        frame[28] = 1;
        frame[29] = 50;
        frame[30] = 1;
        frame[31] = 1;
        frame[32] = 1;
        frame[33] = 1;
        frame[34] = 0xD4;
        frame[35] = 0x31; // port 54321
        frame[36] = 0x01;
        frame[37] = 0xBB; // port 443
        frame[46] = 0x50; // TCP Data offset = 5 words (20 bytes)

        let counter = AtomicU64::new(0);
        let local_ips = Arc::new(Mutex::new(vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))]));
        // PACKET_OUTGOING = 4
        let packet = LiveTrafficSniffer::parse_ethernet_frame_with_meta(&frame, 4, 1, &counter, &local_ips)
            .expect("Must parse valid IPv4 TCP frame");

        assert_eq!(packet.protocol, "TCP");
        assert_eq!(packet.src_addr, "192.168.1.50");
        assert_eq!(packet.dst_addr, "1.1.1.1");
        assert_eq!(packet.src_port, Some(54321));
        assert_eq!(packet.dst_port, Some(443));
        assert_eq!(packet.direction, PacketDirection::Outbound);
    }

    #[test]
    fn test_parse_ipv4_non_initial_fragment() {
        let mut frame = vec![0u8; 60];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[14] = 0x45;
        frame[16] = 0x00;
        frame[17] = 46; // Total Length
        // Fragment offset = 185 (0x00B9) -> non-initial fragment
        frame[20] = 0x00;
        frame[21] = 0xB9;
        frame[23] = 6; // Protocol = TCP
        frame[26] = 10;
        frame[27] = 0;
        frame[28] = 0;
        frame[29] = 1;
        frame[30] = 10;
        frame[31] = 0;
        frame[32] = 0;
        frame[33] = 2;

        let counter = AtomicU64::new(0);
        let local_ips = Arc::new(Mutex::new(vec![]));
        let packet = LiveTrafficSniffer::parse_ethernet_frame(&frame, &counter, &local_ips)
            .expect("Must parse fragment");

        assert_eq!(packet.protocol, "IPv4-Frag");
        assert_eq!(packet.src_port, None);
    }

    #[test]
    fn test_parse_ipv6_with_extension_header() {
        let mut frame = vec![0u8; 70];
        frame[12] = 0x86;
        frame[13] = 0xDD; // IPv6 EtherType
        frame[14] = 0x60; // Version 6
        frame[18] = 0x00;
        frame[19] = 16;   // Payload length = 16 bytes
        frame[20] = 0;    // Next Header = Hop-by-Hop (0)
        // Hop-by-Hop header at offset 54 (14 + 40):
        frame[54] = 6;    // Next Header inside Hop-by-Hop is TCP (6)
        frame[55] = 0;    // Header Ext Length: 0 (meaning 8 bytes total)
        // TCP ports at offset 62 (54 + 8):
        frame[62] = 0x01;
        frame[63] = 0xBB; // 443
        frame[64] = 0x1F;
        frame[65] = 0x90; // 8080

        let counter = AtomicU64::new(0);
        let local_ips = Arc::new(Mutex::new(vec![]));
        let packet = LiveTrafficSniffer::parse_ethernet_frame(&frame, &counter, &local_ips)
            .expect("Must parse IPv6 with extension header");

        assert_eq!(packet.protocol, "TCP");
        assert_eq!(packet.src_port, Some(443));
        assert_eq!(packet.dst_port, Some(8080));
    }
}
