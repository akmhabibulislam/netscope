use chrono::Utc;
use netscope_core::{
    CapturedPacketSummary, FlowProtocol, FlowTracker, NetworkFlow, PacketDirection,
};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use tracing::{info, warn};

/// RAII wrapper for POSIX socket file descriptor ensuring cleanup on all exit/error paths
struct RawSocket(libc::c_int);

impl RawSocket {
    fn new(fd: libc::c_int) -> Self {
        Self(fd)
    }

    fn as_raw_fd(&self) -> libc::c_int {
        self.0
    }

    fn into_raw_fd(mut self) -> libc::c_int {
        let fd = self.0;
        self.0 = -1; // disarm Drop
        fd
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

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
    flow_tracker: Arc<Mutex<FlowTracker>>,
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
            flow_tracker: self.flow_tracker.clone(),
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
            flow_tracker: Arc::new(Mutex::new(FlowTracker::new(10000))),
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
        self.state
            .lock()
            .map(|s| *s)
            .unwrap_or(CaptureState::Stopped)
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

    pub fn start_capture(&self) -> Result<(), String> {
        self.start_capture_on(None)
    }

    pub fn start_capture_on(&self, interface: Option<&str>) -> Result<(), String> {
        let mut state_guard = self.state.lock().map_err(|e| e.to_string())?;
        if *state_guard == CaptureState::Running || *state_guard == CaptureState::Starting {
            return Ok(());
        }

        *state_guard = CaptureState::Starting;
        if let Ok(mut err) = self.last_error.lock() {
            *err = None;
        }

        // 1. Create raw socket with RAII guard to guarantee closure on any failure
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            )
        };

        if raw_fd < 0 {
            let errno = unsafe { *libc::__errno_location() };
            let err_msg = if errno == libc::EPERM || errno == libc::EACCES {
                "AF_PACKET raw socket permission denied: CAP_NET_RAW capability required."
                    .to_string()
            } else {
                format!("Failed to create AF_PACKET raw socket (errno: {})", errno)
            };
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

        let socket = RawSocket::new(raw_fd);

        if let Ok(mut p) = self.has_raw_permission.lock() {
            *p = true;
        }

        // 2. Interface Binding: if an interface is specified, validate and bind using libc::sockaddr_ll
        if let Some(if_name) = interface {
            let c_ifname = std::ffi::CString::new(if_name).map_err(|_| {
                let msg = format!("Interface name '{}' contains invalid null bytes", if_name);
                *state_guard = CaptureState::Failed;
                msg
            })?;

            let ifindex = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) };
            if ifindex == 0 {
                let err_msg = format!("Interface '{}' not found or inactive (ifindex: 0)", if_name);
                if let Ok(mut err) = self.last_error.lock() {
                    *err = Some(err_msg.clone());
                }
                *state_guard = CaptureState::Failed;
                return Err(err_msg);
            }

            let mut bind_addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            bind_addr.sll_family = libc::AF_PACKET as u16;
            bind_addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
            bind_addr.sll_ifindex = ifindex as i32;

            let bind_res = unsafe {
                libc::bind(
                    socket.as_raw_fd(),
                    &bind_addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };

            if bind_res < 0 {
                let errno = unsafe { *libc::__errno_location() };
                let err_msg = format!(
                    "Failed to bind AF_PACKET to interface '{}' (errno: {})",
                    if_name, errno
                );
                if let Ok(mut err) = self.last_error.lock() {
                    *err = Some(err_msg.clone());
                }
                *state_guard = CaptureState::Failed;
                return Err(err_msg);
            }
            info!(
                "Bound live packet socket to interface '{}' (ifindex: {})",
                if_name, ifindex
            );
        }

        // 3. Configure socket timeout (250ms) to allow responsive stop checks
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 250_000,
        };
        let sockopt_res = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            )
        };
        if sockopt_res < 0 {
            let err_msg = "Failed to configure SO_RCVTIMEO on packet socket".to_string();
            if let Ok(mut err) = self.last_error.lock() {
                *err = Some(err_msg.clone());
            }
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
        let flow_tracker_arc = self.flow_tracker.clone();
        let local_ips_arc = self.local_ips.clone();

        *state_guard = CaptureState::Running;

        // Disarm caller RAII guard and transfer ownership to worker thread
        let transfer_fd = socket.into_raw_fd();

        let handle = std::thread::spawn(move || {
            let worker_socket = RawSocket::new(transfer_fd);
            let mut raw_buffer = [0u8; 65535];

            loop {
                if stop_rx.try_recv().is_ok() {
                    break;
                }

                let mut saddr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
                let mut saddr_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

                let n = unsafe {
                    libc::recvfrom(
                        worker_socket.as_raw_fd(),
                        raw_buffer.as_mut_ptr() as *mut libc::c_void,
                        raw_buffer.len(),
                        0,
                        &mut saddr as *mut _ as *mut libc::sockaddr,
                        &mut saddr_len,
                    )
                };

                if n > 14 {
                    let packet_bytes = &raw_buffer[..n as usize];
                    let pkttype = saddr.sll_pkttype;
                    let ifindex = saddr.sll_ifindex;

                    if let Some(packet) = Self::parse_ethernet_frame_with_meta(
                        packet_bytes,
                        pkttype,
                        ifindex,
                        &counter_arc,
                        &local_ips_arc,
                    ) {
                        // Ingest into flow tracker if IP endpoints are present
                        if let (Ok(src_ip), Ok(dst_ip)) = (
                            std::net::IpAddr::from_str(&packet.src_addr),
                            std::net::IpAddr::from_str(&packet.dst_addr),
                        ) {
                            let proto = match packet.protocol.as_str() {
                                "TCP" => FlowProtocol::Tcp,
                                "UDP" => FlowProtocol::Udp,
                                "ICMP" | "ICMPv6" => FlowProtocol::Icmp,
                                _ => FlowProtocol::Other(0),
                            };
                            let sp = packet.src_port.unwrap_or(0);
                            let dp = packet.dst_port.unwrap_or(0);
                            if let Ok(mut tracker) = flow_tracker_arc.lock() {
                                tracker.process_packet(
                                    src_ip,
                                    sp,
                                    dst_ip,
                                    dp,
                                    proto,
                                    packet.length_bytes,
                                    packet.tcp_flags,
                                );
                            }
                        }

                        if let Ok(mut q) = buffer_arc.lock() {
                            if q.len() >= 5000 {
                                q.pop_front();
                            }
                            q.push_back(packet);
                        }
                    }
                }
            }

            // worker_socket dropped here, calling libc::close
            drop(worker_socket);

            if let Ok(mut st) = state_arc.lock() {
                *st = CaptureState::Stopped;
            }
        });

        if let Ok(mut h) = self.worker_handle.lock() {
            *h = Some(handle);
        }

        Ok(())
    }

    pub fn stop_capture(&self) {
        if let Ok(mut state_guard) = self.state.lock() {
            if *state_guard != CaptureState::Running {
                return;
            }
            *state_guard = CaptureState::Stopping;
        }

        if let Ok(mut sig) = self.stop_signal.lock() {
            if let Some(tx) = sig.take() {
                let _ = tx.send(());
            }
        }

        if let Ok(mut h) = self.worker_handle.lock() {
            if let Some(handle) = h.take() {
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

    pub fn get_active_flows(&self) -> Vec<NetworkFlow> {
        if let Ok(mut tracker) = self.flow_tracker.lock() {
            tracker.cleanup_expired();
            tracker.active_flows()
        } else {
            Vec::new()
        }
    }

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
            0x0800 => Self::parse_ipv4(
                &bytes[offset..],
                bytes.len(),
                sll_pkttype,
                counter,
                local_ips_arc,
            ),
            // IPv6 Frame
            0x86DD => Self::parse_ipv6(
                &bytes[offset..],
                bytes.len(),
                sll_pkttype,
                counter,
                local_ips_arc,
            ),
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
            summary: format!(
                "{} (Who has {}? Tell {}) [{} bytes]",
                op_name, dst_ip, src_ip, total_frame_len
            ),
            tcp_flags: None,
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

        let total_length = u16::from_be_bytes([ip_bytes[2], ip_bytes[3]]) as usize;
        if total_length > ip_bytes.len() || total_length < ihl {
            return None;
        }

        let flags_frag = u16::from_be_bytes([ip_bytes[6], ip_bytes[7]]);
        let frag_offset = (flags_frag & 0x1FFF) * 8;
        let is_non_initial_fragment = frag_offset > 0;

        let protocol_num = ip_bytes[9];
        let src_ip = Ipv4Addr::new(ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]);
        let dst_ip = Ipv4Addr::new(ip_bytes[16], ip_bytes[17], ip_bytes[18], ip_bytes[19]);

        let payload = &ip_bytes[ihl..total_length];

        let (src_port, dst_port, tcp_flags, proto_name, app_info) = if is_non_initial_fragment {
            (None, None, None, "IPv4-Frag", "IPv4 Non-Initial Fragment")
        } else {
            match protocol_num {
                6 => {
                    // TCP (minimum header 20 bytes)
                    if payload.len() >= 20 {
                        let sp = u16::from_be_bytes([payload[0], payload[1]]);
                        let dp = u16::from_be_bytes([payload[2], payload[3]]);
                        let data_offset = ((payload[12] >> 4) as usize) * 4;
                        if data_offset < 20 || data_offset > payload.len() {
                            (None, None, None, "TCP", "TCP (Malformed Data Offset)")
                        } else {
                            let flags = payload[13];
                            let app = match (sp, dp) {
                                (443, _) | (_, 443) => "TLS/HTTPS",
                                (80, _) | (_, 80) => "HTTP",
                                (53, _) | (_, 53) => "DNS-over-TCP",
                                (22, _) | (_, 22) => "SSH",
                                _ => "TCP",
                            };
                            (Some(sp), Some(dp), Some(flags), "TCP", app)
                        }
                    } else {
                        (None, None, None, "TCP", "TCP (Truncated Header)")
                    }
                }
                17 => {
                    // UDP (Header 8 bytes)
                    if payload.len() >= 8 {
                        let sp = u16::from_be_bytes([payload[0], payload[1]]);
                        let dp = u16::from_be_bytes([payload[2], payload[3]]);
                        let udp_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
                        if udp_len < 8 || udp_len > payload.len() {
                            (None, None, None, "UDP", "UDP (Length Mismatch)")
                        } else {
                            let app = match (sp, dp) {
                                (53, _) | (_, 53) => "DNS",
                                (67, _) | (_, 67) | (68, _) | (_, 68) => "DHCP",
                                (443, _) | (_, 443) => "QUIC/HTTP3",
                                (123, _) | (_, 123) => "NTP",
                                _ => "UDP",
                            };
                            (Some(sp), Some(dp), None, "UDP", app)
                        }
                    } else {
                        (None, None, None, "UDP", "UDP (Truncated Header)")
                    }
                }
                1 => {
                    // ICMP
                    let icmp_type = if !payload.is_empty() { payload[0] } else { 255 };
                    let (sp, dp) = if payload.len() >= 8 && (icmp_type == 8 || icmp_type == 0) {
                        let id = u16::from_be_bytes([payload[4], payload[5]]);
                        (Some(id), Some(id))
                    } else if payload.len() >= 2 {
                        (Some(payload[0] as u16), Some(payload[1] as u16))
                    } else {
                        (None, None)
                    };

                    let desc = match icmp_type {
                        0 => "ICMP Echo Reply",
                        8 => "ICMP Echo Request",
                        3 => "ICMP Dest Unreachable",
                        11 => "ICMP Time Exceeded",
                        _ => "ICMP Control",
                    };
                    (sp, dp, None, "ICMP", desc)
                }
                50 => (
                    None,
                    None,
                    None,
                    "ESP",
                    "IPsec Encapsulated Security Payload (Encrypted)",
                ),
                51 => (None, None, None, "AH", "IPsec Authentication Header"),
                _ => (None, None, None, "IPv4", "Raw IPv4 Protocol"),
            }
        };

        let is_outbound = match sll_pkttype {
            4 => true,      // PACKET_OUTGOING
            0..=3 => false, // PACKET_HOST, BROADCAST, MULTICAST, OTHERHOST
            _ => {
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
            tcp_flags,
        })
    }

    /// Parse IPv6 packet with RFC 8200 Extension Header traversal and TCP flags extraction
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
                    let frag_offset =
                        u16::from_be_bytes([ip_bytes[offset + 2], ip_bytes[offset + 3]]) >> 3;
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
                // ESP or terminal
                50 => break,
                _ => break,
            }
        }

        let payload = if offset <= ip_bytes.len() {
            &ip_bytes[offset..]
        } else {
            &[]
        };

        let (src_port, dst_port, tcp_flags, proto_name, app_info) = if is_non_initial_fragment {
            (None, None, None, "IPv6-Frag", "IPv6 Fragment Continuation")
        } else {
            match next_header {
                6 => {
                    // TCP
                    if payload.len() >= 20 {
                        let sp = u16::from_be_bytes([payload[0], payload[1]]);
                        let dp = u16::from_be_bytes([payload[2], payload[3]]);
                        let data_offset = ((payload[12] >> 4) as usize) * 4;
                        if data_offset < 20 || data_offset > payload.len() {
                            (None, None, None, "TCP", "TCP (Malformed Data Offset)")
                        } else {
                            let flags = payload[13];
                            let app = match (sp, dp) {
                                (443, _) | (_, 443) => "TLS/HTTPS",
                                (80, _) | (_, 80) => "HTTP",
                                (53, _) | (_, 53) => "DNS",
                                (22, _) | (_, 22) => "SSH",
                                _ => "TCP",
                            };
                            (Some(sp), Some(dp), Some(flags), "TCP", app)
                        }
                    } else {
                        (None, None, None, "TCP", "TCP (Truncated Header)")
                    }
                }
                17 => {
                    // UDP
                    if payload.len() >= 8 {
                        let sp = u16::from_be_bytes([payload[0], payload[1]]);
                        let dp = u16::from_be_bytes([payload[2], payload[3]]);
                        let udp_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
                        if udp_len < 8 || udp_len > payload.len() {
                            (None, None, None, "UDP", "UDP (Length Mismatch)")
                        } else {
                            let app = match (sp, dp) {
                                (53, _) | (_, 53) => "DNS",
                                (443, _) | (_, 443) => "QUIC",
                                _ => "UDP",
                            };
                            (Some(sp), Some(dp), None, "UDP", app)
                        }
                    } else {
                        (None, None, None, "UDP", "UDP (Truncated Header)")
                    }
                }
                58 => {
                    // ICMPv6
                    let (sp, dp) = if payload.len() >= 8 && (payload[0] == 128 || payload[0] == 129)
                    {
                        let id = u16::from_be_bytes([payload[4], payload[5]]);
                        (Some(id), Some(id))
                    } else if payload.len() >= 2 {
                        (Some(payload[0] as u16), Some(payload[1] as u16))
                    } else {
                        (None, None)
                    };
                    (sp, dp, None, "ICMPv6", "ICMPv6 Control")
                }
                50 => (
                    None,
                    None,
                    None,
                    "ESP",
                    "IPsec Encapsulated Security Payload (Encrypted)",
                ),
                51 => (None, None, None, "AH", "IPsec Authentication Header"),
                _ => (None, None, None, "IPv6", "IPv6 NextHeader"),
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
            tcp_flags,
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
        let counter = AtomicU64::new(0);
        let mut frame = vec![0u8; 42];
        frame[0..6].copy_from_slice(&[0xFF; 6]);
        frame[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // ARP

        frame[14..16].copy_from_slice(&1u16.to_be_bytes()); // Eth
        frame[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); // IP
        frame[18] = 6;
        frame[19] = 4;
        frame[20..22].copy_from_slice(&1u16.to_be_bytes()); // Request

        // Sender IP: 192.168.1.1
        frame[28..32].copy_from_slice(&[192, 168, 1, 1]);
        // Target IP: 192.168.1.100
        frame[38..42].copy_from_slice(&[192, 168, 1, 100]);

        let local_ips = Arc::new(Mutex::new(Vec::new()));
        let res = LiveTrafficSniffer::parse_ethernet_frame(&frame, &counter, &local_ips)
            .expect("Must parse ARP");
        assert_eq!(res.protocol, "ARP");
        assert_eq!(res.src_addr, "192.168.1.1");
        assert_eq!(res.dst_addr, "192.168.1.100");
    }

    #[test]
    fn test_parse_valid_ipv4_tcp_frame_extracts_flags() {
        let counter = AtomicU64::new(0);
        let mut frame = vec![0u8; 54];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4

        // IPv4 Header
        frame[14] = 0x45; // Version 4, IHL 5 (20 bytes)
        frame[16..18].copy_from_slice(&40u16.to_be_bytes()); // Total length: 20 IP + 20 TCP
        frame[23] = 6; // TCP
        frame[26..30].copy_from_slice(&[10, 0, 0, 1]); // src
        frame[30..34].copy_from_slice(&[10, 0, 0, 2]); // dst

        // TCP Header (offset 34)
        frame[34..36].copy_from_slice(&54321u16.to_be_bytes()); // src port
        frame[36..38].copy_from_slice(&443u16.to_be_bytes()); // dst port: 443
        frame[46] = 0x50; // Data offset 5 (20 bytes)
        frame[47] = 0x12; // SYN-ACK (0x02 | 0x10)

        let local_ips = Arc::new(Mutex::new(Vec::new()));
        let res = LiveTrafficSniffer::parse_ethernet_frame(&frame, &counter, &local_ips)
            .expect("Must parse valid IPv4 TCP frame");

        assert_eq!(res.protocol, "TCP");
        assert_eq!(res.src_port, Some(54321));
        assert_eq!(res.dst_port, Some(443));
        assert_eq!(res.tcp_flags, Some(0x12)); // SYN-ACK extracted!
    }

    #[test]
    fn test_parse_ipv4_truncated_tcp_header_rejects_ports() {
        let counter = AtomicU64::new(0);
        let mut frame = vec![0u8; 40]; // Only 6 bytes of TCP payload
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&26u16.to_be_bytes()); // 20 IP + 6 TCP
        frame[23] = 6; // TCP
        frame[26..30].copy_from_slice(&[10, 0, 0, 1]);
        frame[30..34].copy_from_slice(&[10, 0, 0, 2]);

        let local_ips = Arc::new(Mutex::new(Vec::new()));
        let res = LiveTrafficSniffer::parse_ethernet_frame(&frame, &counter, &local_ips)
            .expect("Must parse IP summary");

        assert_eq!(res.protocol, "TCP");
        assert_eq!(res.src_port, None); // Truncated header MUST NOT report ports!
        assert_eq!(res.dst_port, None);
        assert_eq!(res.tcp_flags, None);
    }

    #[test]
    fn test_parse_ipv4_non_initial_fragment() {
        let counter = AtomicU64::new(0);
        let mut frame = vec![0u8; 38];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&24u16.to_be_bytes());
        // Fragment offset = 185 (0x00B9)
        frame[20..22].copy_from_slice(&0x00B9u16.to_be_bytes());
        frame[23] = 6; // TCP
        frame[26..30].copy_from_slice(&[192, 168, 1, 5]);
        frame[30..34].copy_from_slice(&[8, 8, 8, 8]);

        let local_ips = Arc::new(Mutex::new(Vec::new()));
        let res = LiveTrafficSniffer::parse_ethernet_frame(&frame, &counter, &local_ips)
            .expect("Must parse fragment");
        assert_eq!(res.protocol, "IPv4-Frag");
        assert_eq!(res.src_port, None);
        assert_eq!(res.dst_port, None);
    }

    #[test]
    fn test_parse_ipv6_with_extension_header_and_tcp_flags() {
        let counter = AtomicU64::new(0);
        let mut frame = vec![0u8; 82]; // 14 eth + 40 ipv6 + 8 hop-by-hop + 20 tcp
        frame[12..14].copy_from_slice(&0x86DDu16.to_be_bytes()); // IPv6

        // IPv6 Header (offset 14)
        frame[14] = 0x60; // Version 6
        frame[18..20].copy_from_slice(&28u16.to_be_bytes()); // Payload len: 8 hop + 20 tcp
        frame[20] = 0; // NextHeader: Hop-by-Hop (0)
        frame[22..38]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // 2001:db8::1
        frame[38..54]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]); // 2001:db8::2

        // Hop-by-Hop Extension Header (offset 54)
        frame[54] = 6; // Next Header: TCP
        frame[55] = 0; // Length: (0 + 1) * 8 = 8 bytes

        // TCP Header (offset 62)
        frame[62..64].copy_from_slice(&44332u16.to_be_bytes());
        frame[64..66].copy_from_slice(&80u16.to_be_bytes());
        frame[74] = 0x50; // Data offset 20
        frame[75] = 0x02; // SYN flag

        let local_ips = Arc::new(Mutex::new(Vec::new()));
        let res = LiveTrafficSniffer::parse_ethernet_frame(&frame, &counter, &local_ips)
            .expect("Must parse IPv6 with extension header");
        assert_eq!(res.protocol, "TCP");
        assert_eq!(res.src_port, Some(44332));
        assert_eq!(res.dst_port, Some(80));
        assert_eq!(res.tcp_flags, Some(0x02));
    }

    #[test]
    fn test_parse_vlan_8021q_frame() {
        let counter = AtomicU64::new(0);
        let mut frame = vec![0u8; 58]; // 14 eth + 4 vlan + 40 ipv4-tcp
        frame[12..14].copy_from_slice(&0x8100u16.to_be_bytes()); // 802.1Q VLAN
        frame[14..16].copy_from_slice(&100u16.to_be_bytes()); // VLAN ID 100
        frame[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); // Inner EtherType: IPv4

        // IPv4 Header at offset 18
        frame[18] = 0x45;
        frame[20..22].copy_from_slice(&40u16.to_be_bytes());
        frame[27] = 6; // TCP
        frame[30..34].copy_from_slice(&[192, 168, 1, 10]);
        frame[34..38].copy_from_slice(&[192, 168, 1, 20]);

        // TCP at offset 38
        frame[38..40].copy_from_slice(&1234u16.to_be_bytes());
        frame[40..42].copy_from_slice(&80u16.to_be_bytes());
        frame[50] = 0x50;
        frame[51] = 0x10; // ACK

        let local_ips = Arc::new(Mutex::new(Vec::new()));
        let res = LiveTrafficSniffer::parse_ethernet_frame(&frame, &counter, &local_ips)
            .expect("Must parse 802.1Q tagged frame");
        assert_eq!(res.protocol, "TCP");
        assert_eq!(res.src_port, Some(1234));
        assert_eq!(res.dst_port, Some(80));
        assert_eq!(res.tcp_flags, Some(0x10));
    }
}
