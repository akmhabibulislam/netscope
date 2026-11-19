use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFlow {
    pub key: FlowKey,
    pub start_time: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub state: String,
}

impl NetworkFlow {
    pub fn new(key: FlowKey, initial_bytes: usize, is_outbound: bool) -> Self {
        let now = Utc::now();
        Self {
            key,
            start_time: now,
            last_seen: now,
            packets_sent: if is_outbound { 1 } else { 0 },
            packets_received: if !is_outbound { 1 } else { 0 },
            bytes_sent: if is_outbound { initial_bytes as u64 } else { 0 },
            bytes_received: if !is_outbound { initial_bytes as u64 } else { 0 },
            state: "Active".to_string(),
        }
    }

    pub fn update(&mut self, bytes: usize, is_outbound: bool) {
        self.last_seen = Utc::now();
        if is_outbound {
            self.packets_sent += 1;
            self.bytes_sent += bytes as u64;
        } else {
            self.packets_received += 1;
            self.bytes_received += bytes as u64;
        }
    }

    pub fn duration_seconds(&self) -> i64 {
        (self.last_seen - self.start_time).num_seconds().max(1)
    }
}
