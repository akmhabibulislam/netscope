use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QuotaPeriod {
    Daily,
    Monthly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QuotaAlertStatus {
    Normal,
    Warning50,
    Warning80,
    Warning95,
    Exceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataUsageQuota {
    pub enabled: bool,
    pub period: QuotaPeriod,
    pub limit_bytes: u64,
    pub current_usage_bytes: u64,
}

impl DataUsageQuota {
    pub fn new(period: QuotaPeriod, limit_mb: u64) -> Self {
        Self {
            enabled: true,
            period,
            limit_bytes: limit_mb * 1024 * 1024,
            current_usage_bytes: 0,
        }
    }

    pub fn usage_percent(&self) -> f64 {
        if self.limit_bytes == 0 {
            return 0.0;
        }
        (self.current_usage_bytes as f64 / self.limit_bytes as f64) * 100.0
    }

    pub fn check_status(&self) -> QuotaAlertStatus {
        if !self.enabled || self.limit_bytes == 0 {
            return QuotaAlertStatus::Normal;
        }
        let pct = self.usage_percent();
        if pct >= 100.0 {
            QuotaAlertStatus::Exceeded
        } else if pct >= 95.0 {
            QuotaAlertStatus::Warning95
        } else if pct >= 80.0 {
            QuotaAlertStatus::Warning80
        } else if pct >= 50.0 {
            QuotaAlertStatus::Warning50
        } else {
            QuotaAlertStatus::Normal
        }
    }
}
