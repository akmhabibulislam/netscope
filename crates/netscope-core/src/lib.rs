pub mod timeline;
pub mod profile;
pub mod quota;
pub mod custom_rule;
pub mod sniffer;

pub use sniffer::{CapturedPacketSummary, PacketDirection};
pub use timeline::{NetworkEvent, TimelineEventType};
pub use profile::NetworkProfile;
pub use quota::{DataUsageQuota, QuotaPeriod, QuotaAlertStatus};
pub use custom_rule::{CustomNetworkRule, RuleAction, RuleCondition};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InterfaceType {
    Loopback,
    Ethernet,
    WiFi,
    Bridge,
    Vlan,
    Vpn,
    Tunnel,
    Virtual,
    Unknown(String),
}

impl std::fmt::Display for InterfaceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Loopback => write!(f, "Loopback"),
            Self::Ethernet => write!(f, "Ethernet"),
            Self::WiFi => write!(f, "Wi-Fi"),
            Self::Bridge => write!(f, "Bridge"),
            Self::Vlan => write!(f, "VLAN"),
            Self::Vpn => write!(f, "VPN / WireGuard"),
            Self::Tunnel => write!(f, "Tunnel"),
            Self::Virtual => write!(f, "Virtual"),
            Self::Unknown(s) => write!(f, "{}", s),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OperState {
    Up,
    Down,
    Unknown,
}

impl std::fmt::Display for OperState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Up => write!(f, "Up"),
            Self::Down => write!(f, "Down"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

impl Default for InterfaceStats {
    fn default() -> Self {
        Self {
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            rx_errors: 0,
            tx_errors: 0,
            rx_dropped: 0,
            tx_dropped: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub if_index: u32,
    pub if_type: InterfaceType,
    pub oper_state: OperState,
    pub mac_address: Option<String>,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub mtu: u32,
    pub is_up: bool,
    pub is_loopback: bool,
    pub is_default: bool,
    pub stats: InterfaceStats,
    pub rx_speed_bps: f64,
    pub tx_speed_bps: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthSample {
    pub timestamp: DateTime<Utc>,
    pub rx_bytes_total: u64,
    pub tx_bytes_total: u64,
    pub rx_speed_bps: f64,
    pub tx_speed_bps: f64,
    pub active_interface: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Unknown,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Icmp => write!(f, "ICMP"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnectionState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Closed,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    Connected, // for UDP
    Unknown(u8),
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Established => write!(f, "ESTABLISHED"),
            Self::SynSent => write!(f, "SYN_SENT"),
            Self::SynRecv => write!(f, "SYN_RECV"),
            Self::FinWait1 => write!(f, "FIN_WAIT1"),
            Self::FinWait2 => write!(f, "FIN_WAIT2"),
            Self::TimeWait => write!(f, "TIME_WAIT"),
            Self::Closed => write!(f, "CLOSED"),
            Self::CloseWait => write!(f, "CLOSE_WAIT"),
            Self::LastAck => write!(f, "LAST_ACK"),
            Self::Listen => write!(f, "LISTEN"),
            Self::Closing => write!(f, "CLOSING"),
            Self::Connected => write!(f, "CONNECTED"),
            Self::Unknown(c) => write!(f, "STATE_{}", c),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMetadata {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<PathBuf>,
    pub cmdline: Vec<String>,
    pub uid: u32,
    pub user: Option<String>,
    pub start_time: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub id: String,
    pub protocol: Protocol,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub state: ConnectionState,
    pub inode: u64,
    pub process: Option<ProcessMetadata>,
    pub reverse_dns: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub asn: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub query: String,
    pub qtype: String,
    pub response: Option<String>,
    pub resolver: String,
    pub duration_ms: Option<u64>,
    pub process_name: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub severity: AlertSeverity,
    pub title: String,
    pub message: String,
    pub rule_id: String,
    pub affected_process: Option<String>,
    pub remote_ip: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub recommendations: Vec<String>,
    pub reviewed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub polling_interval_ms: u64,
    pub enable_external_lookups: bool,
    pub external_lookup_provider: String,
    pub retention_days: u32,
    pub dark_theme: bool,
    pub show_tray: bool,
    pub start_minimized: bool,
    pub active_profile: String,
    pub whitelisted_ips: Vec<String>,
    pub whitelisted_processes: Vec<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            polling_interval_ms: 1000,
            enable_external_lookups: false,
            external_lookup_provider: "ip-api".to_string(),
            retention_days: 30,
            dark_theme: true,
            show_tray: true,
            start_minimized: false,
            active_profile: "Default".to_string(),
            whitelisted_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
            whitelisted_processes: vec!["systemd-resolved".to_string(), "NetworkManager".to_string()],
        }
    }
}
