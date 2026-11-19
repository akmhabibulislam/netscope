use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TimelineEventType {
    InterfaceChanged,
    VpnStateChanged,
    ConnectionOpened,
    ConnectionClosed,
    DnsQueried,
    TrafficSpike,
    SecurityAlert,
    QuotaWarning,
    ProfileSwitched,
}

impl std::fmt::Display for TimelineEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InterfaceChanged => write!(f, "INTERFACE_CHANGE"),
            Self::VpnStateChanged => write!(f, "VPN_CHANGE"),
            Self::ConnectionOpened => write!(f, "CONN_OPEN"),
            Self::ConnectionClosed => write!(f, "CONN_CLOSE"),
            Self::DnsQueried => write!(f, "DNS_QUERY"),
            Self::TrafficSpike => write!(f, "TRAFFIC_SPIKE"),
            Self::SecurityAlert => write!(f, "SECURITY_ALERT"),
            Self::QuotaWarning => write!(f, "QUOTA_WARNING"),
            Self::ProfileSwitched => write!(f, "PROFILE_SWITCH"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: TimelineEventType,
    pub title: String,
    pub details: String,
    pub process: Option<String>,
    pub ip_or_domain: Option<String>,
}
