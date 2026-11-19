use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PacketDirection {
    Inbound,
    Outbound,
}

impl std::fmt::Display for PacketDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inbound => write!(f, "INBOUND"),
            Self::Outbound => write!(f, "OUTBOUND"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedPacketSummary {
    pub id: u64,
    pub timestamp: DateTime<Utc>,
    pub direction: PacketDirection,
    pub protocol: String,
    pub src_addr: String,
    pub src_port: Option<u16>,
    pub dst_addr: String,
    pub dst_port: Option<u16>,
    pub length_bytes: usize,
    pub summary: String,
}
