use chrono::Utc;
use netscope_core::{CapturedPacketSummary, PacketDirection};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

#[derive(Clone)]
pub struct LiveTrafficSniffer {
    is_running: Arc<AtomicBool>,
    has_raw_permission: Arc<AtomicBool>,
    last_error: Arc<Mutex<Option<String>>>,
    packet_counter: Arc<AtomicU64>,
    captured_packets: Arc<Mutex<VecDeque<CapturedPacketSummary>>>,
    local_ips: Arc<Mutex<Vec<IpAddr>>>,
}

impl LiveTrafficSniffer {
    pub fn new() -> Self {
        Self {
            is_running: Arc::new(AtomicBool::new(false)),
            has_raw_permission: Arc::new(AtomicBool::new(false)),
            last_error: Arc::new(Mutex::new(None)),
            packet_counter: Arc::new(AtomicU64::new(0)),
            captured_packets: Arc::new(Mutex::new(VecDeque::with_capacity(2000))),
            local_ips: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn set_local_ips(&self, ips: Vec<IpAddr>) {
        if let Ok(mut l) = self.local_ips.lock() {
            *l = ips;
        }
    }

    pub fn has_raw_permission(&self) -> bool {
        self.has_raw_permission.load(Ordering::SeqCst)
    }

    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    pub fn get_last_error(&self) -> Option<String> {
        self.last_error.lock().ok().and_then(|e| e.clone())
    }

    /// Starts capture on a background thread.
    /// Safely handles permission failures by clearing `is_running` so the application never gets stuck.
    pub fn start_capture(&self) -> Result<(), String> {
        if self.is_running.swap(true, Ordering::SeqCst) {
            return Ok(()); // Already running
        }

        info!("Initializing live packet sniffer engine");
        let is_running = self.is_running.clone();
        let counter = self.packet_counter.clone();
        let buffer = self.captured_packets.clone();
        let local_ips_arc = self.local_ips.clone();
        let has_raw_perm = self.has_raw_permission.clone();
        let last_err_arc = self.last_error.clone();

        // Clear previous error
        if let Ok(mut err) = last_err_arc.lock() {
            *err = None;
        }

        std::thread::spawn(move || {
            // AF_PACKET raw socket in Linux (needs CAP_NET_RAW or root)
            let socket_fd = unsafe {
                libc::socket(
                    libc::AF_PACKET,
                    libc::SOCK_RAW,
                    (libc::ETH_P_ALL as u16).to_be() as i32,
                )
            };

            if socket_fd < 0 {
                let err_msg = "AF_PACKET raw socket access denied. CAP_NET_RAW capability required.".to_string();
                has_raw_perm.store(false, Ordering::SeqCst);
                // RESET is_running so the sniffer is not permanently trapped in running state
                is_running.store(false, Ordering::SeqCst);
                if let Ok(mut err) = last_err_arc.lock() {
                    *err = Some(err_msg.clone());
                }
                warn!(
                    "Live packet capture disabled: {}. Set CAP_NET_RAW: \
                     'sudo setcap cap_net_raw,cap_net_admin+eip <binary>'. \
                     No simulated or fake traffic will be generated.",
                    err_msg
                );
                return;
            }

            has_raw_perm.store(true, Ordering::SeqCst);
            info!("Live AF_PACKET raw socket successfully bound to network interface");

            // Configure socket timeout: 500ms so thread responds promptly to stop_capture
            let tv = libc::timeval {
                tv_sec: 0,
                tv_usec: 500_000,
            };
            unsafe {
                libc::setsockopt(
                    socket_fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &tv as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::timeval>() as u32,
                );
            }

            let mut raw_buffer = [0u8; 65535];

            while is_running.load(Ordering::SeqCst) {
                let n = unsafe {
                    libc::recvfrom(
                        socket_fd,
                        raw_buffer.as_mut_ptr() as *mut libc::c_void,
                        raw_buffer.len(),
                        0,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                };

                if n > 14 {
                    let packet_bytes = &raw_buffer[..n as usize];
                    if let Some(packet) = Self::parse_ethernet_frame(packet_bytes, &counter, &local_ips_arc) {
                        if let Ok(mut q) = buffer.lock() {
                            if q.len() >= 2000 {
                                q.pop_front();
                            }
                            q.push_back(packet);
                        }
                    }
                }
            }

            unsafe { libc::close(socket_fd) };
            is_running.store(false, Ordering::SeqCst);
            info!("Live packet sniffer stopped cleanly");
        });

        Ok(())
    }

    pub fn stop_capture(&self) {
        self.is_running.store(false, Ordering::SeqCst);
    }

    pub fn get_recent_packets(&self, limit: usize) -> Vec<CapturedPacketSummary> {
        if let Ok(q) = self.captured_packets.lock() {
            q.iter().rev().take(limit).cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Comprehensive Ethernet frame parser supporting VLAN tags (802.1Q), IPv4 (with fragment offset check),
    /// and IPv6 (with full Extension Header traversal)
    pub fn parse_ethernet_frame(
        bytes: &[u8],
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
            0x0800 => Self::parse_ipv4(&bytes[offset..], bytes.len(), counter, local_ips_arc),
            // IPv6 Frame
            0x86DD => Self::parse_ipv6(&bytes[offset..], bytes.len(), counter, local_ips_arc),
            // ARP
            0x0806 => {
                let id = counter.fetch_add(1, Ordering::SeqCst);
                Some(CapturedPacketSummary {
                    id,
                    timestamp: Utc::now(),
                    direction: PacketDirection::Inbound,
                    protocol: "ARP".to_string(),
                    src_addr: "Broadcast".to_string(),
                    src_port: None,
                    dst_addr: "Broadcast".to_string(),
                    dst_port: None,
                    length_bytes: bytes.len(),
                    summary: format!("Address Resolution Protocol frame [{} bytes]", bytes.len()),
                })
            }
            _ => None,
        }
    }

    fn parse_ipv4(
        ip_bytes: &[u8],
        total_frame_len: usize,
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

        // IPv4 Fragmentation handling:
        // Byte 6-7: Flags (3 bits) + Fragment Offset (13 bits in 8-byte units)
        let flags_frag = u16::from_be_bytes([ip_bytes[6], ip_bytes[7]]);
        let frag_offset = (flags_frag & 0x1FFF) * 8;
        let is_non_initial_fragment = frag_offset > 0;

        let protocol_num = ip_bytes[9];
        let src_ip = Ipv4Addr::new(ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]);
        let dst_ip = Ipv4Addr::new(ip_bytes[16], ip_bytes[17], ip_bytes[18], ip_bytes[19]);

        let payload = &ip_bytes[ihl..];

        // If this is a non-initial fragment, the payload does NOT start with a transport header
        let (src_port, dst_port, proto_name, app_info) = if is_non_initial_fragment {
            (
                None,
                None,
                "IPv4-Frag",
                "IPv4 Non-Initial Fragment (payload continues prior packet)",
            )
        } else {
            match protocol_num {
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
                            "DNS-over-TCP"
                        } else if sp == 22 || dp == 22 {
                            "SSH"
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
                    } else {
                        (None, None, "UDP", "UDP")
                    }
                }
                1 => (None, None, "ICMP", "ICMP Echo/Control"),
                _ => (None, None, "IPv4", "Raw IPv4 Protocol"),
            }
        };

        let is_outbound = if let Ok(ips) = local_ips_arc.lock() {
            ips.contains(&IpAddr::V4(src_ip))
        } else {
            src_ip.is_private()
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

        let mut next_header = ip_bytes[6];
        let mut src_octets = [0u8; 16];
        src_octets.copy_from_slice(&ip_bytes[8..24]);
        let src_ip = Ipv6Addr::from(src_octets);

        let mut dst_octets = [0u8; 16];
        dst_octets.copy_from_slice(&ip_bytes[24..40]);
        let dst_ip = Ipv6Addr::from(dst_octets);

        let mut offset = 40;
        let mut is_non_initial_fragment = false;

        // Traverse IPv6 Extension Headers until reaching a terminal transport protocol or No Next Header (59)
        while offset < ip_bytes.len() {
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
                // Terminal Protocol (TCP=6, UDP=17, ICMPv6=58, NoNextHeader=59, etc.)
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
                _ => (None, None, "IPv6", "IPv6 NextHeader"),
            }
        };

        let is_outbound = if let Ok(ips) = local_ips_arc.lock() {
            ips.contains(&IpAddr::V6(src_ip))
        } else {
            src_ip.is_loopback() || src_ip.is_unicast_link_local()
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
    fn test_parse_valid_ipv4_tcp_frame() {
        let mut frame = vec![0u8; 54];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[14] = 0x45; // IPv4, IHL 5
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

        let counter = AtomicU64::new(0);
        let local_ips = Arc::new(Mutex::new(vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))]));
        let packet = LiveTrafficSniffer::parse_ethernet_frame(&frame, &counter, &local_ips)
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
        assert_eq!(packet.src_port, None); // Must not fabricate port from fragmented data
    }

    #[test]
    fn test_parse_ipv6_with_extension_header() {
        let mut frame = vec![0u8; 70];
        frame[12] = 0x86;
        frame[13] = 0xDD; // IPv6 EtherType
        frame[14] = 0x60; // Version 6
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
