use netscope_core::{DataUsageQuota, NetworkProfile};
use netscope_network::{collector::NetworkCollector, sniffer::LiveTrafficSniffer, speedtest::SpeedTestResult};
use netscope_security::SecurityRuleEngine;
use netscope_storage::StorageManager;
use parking_lot::RwLock;
use std::sync::Arc;

#[derive(Clone)]
#[allow(dead_code)]
pub struct AppState {
    pub collector: NetworkCollector,
    pub storage: StorageManager,
    pub rule_engine: Arc<RwLock<SecurityRuleEngine>>,
    pub sniffer: LiveTrafficSniffer,
    pub quota: Arc<RwLock<DataUsageQuota>>,
    pub active_profile: Arc<RwLock<NetworkProfile>>,
    pub latest_speedtest: Arc<RwLock<Option<SpeedTestResult>>>,
}

impl AppState {
    pub fn new() -> Self {
        let collector = NetworkCollector::new();
        let storage = StorageManager::new(None).unwrap_or_else(|_| StorageManager::new_in_memory().unwrap());
        let rule_engine = Arc::new(RwLock::new(SecurityRuleEngine::new(vec![], vec![])));
        let sniffer = LiveTrafficSniffer::new();
        let _ = sniffer.start_capture();

        let quota = Arc::new(RwLock::new(DataUsageQuota::new(netscope_core::QuotaPeriod::Daily, 5000))); // 5GB daily quota
        let active_profile = Arc::new(RwLock::new(NetworkProfile::default()));
        let latest_speedtest = Arc::new(RwLock::new(None));

        Self {
            collector,
            storage,
            rule_engine,
            sniffer,
            quota,
            active_profile,
            latest_speedtest,
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
