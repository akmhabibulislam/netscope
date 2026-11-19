use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkProfile {
    pub id: String,
    pub name: String,
    pub description: String,
    pub is_vpn_required: bool,
    pub alert_sensitivity: String, // "High", "Medium", "Relaxed"
    pub max_daily_mb: Option<u64>,
    pub trusted_ssids: Vec<String>,
}

impl Default for NetworkProfile {
    fn default() -> Self {
        Self {
            id: "default".to_string(),
            name: "Standard Profile".to_string(),
            description: "General profile suitable for home and office networks".to_string(),
            is_vpn_required: false,
            alert_sensitivity: "Medium".to_string(),
            max_daily_mb: None,
            trusted_ssids: vec![],
        }
    }
}
