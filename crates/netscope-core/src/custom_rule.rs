use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCondition {
    ProcessEquals(String),
    DestinationPortEquals(u16),
    UploadSpeedExceedsMbps(f64),
    RemoteIpMatches(String),
    DomainMatches(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleAction {
    AlertNotification,
    PromptTermination,
    LogOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomNetworkRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub condition: RuleCondition,
    pub action: RuleAction,
    pub enabled: bool,
}
