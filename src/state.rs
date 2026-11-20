use netscope_core::{DataUsageQuota, NetworkProfile};
use netscope_network::{
    collector::NetworkCollector, sniffer::LiveTrafficSniffer, speedtest::SpeedTestResult,
};
use netscope_security::SecurityRuleEngine;
use netscope_storage::StorageManager;
use parking_lot::RwLock;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub collector: NetworkCollector,
    pub storage: StorageManager,
    pub storage_degraded_warning: Arc<RwLock<Option<String>>>,
    pub rule_engine: Arc<RwLock<SecurityRuleEngine>>,
    pub sniffer: LiveTrafficSniffer,
    pub quota: Arc<RwLock<DataUsageQuota>>,
    pub active_profile: Arc<RwLock<NetworkProfile>>,
    pub latest_speedtest: Arc<RwLock<Option<SpeedTestResult>>>,
}

impl AppState {
    pub fn new() -> Self {
        let collector = NetworkCollector::new();

        let (storage, storage_degraded_warning) = match StorageManager::new(None) {
            Ok(s) => (s, Arc::new(RwLock::new(None))),
            Err(e) => {
                let warn_msg = format!(
                    "Persistent database unavailable ({}). Running with temporary in-memory storage; historical telemetry will not persist across restarts.",
                    e
                );
                tracing::warn!("{}", warn_msg);
                let in_mem = StorageManager::new_in_memory().unwrap_or_else(|e2| {
                    panic!(
                        "Critical storage initialization failure: unable to create in-memory SQLite: {}",
                        e2
                    );
                });
                (in_mem, Arc::new(RwLock::new(Some(warn_msg))))
            }
        };

        let rule_engine = Arc::new(RwLock::new(SecurityRuleEngine::new(vec![], vec![])));
        let sniffer = LiveTrafficSniffer::new();

        if let Err(e) = sniffer.start_capture() {
            tracing::info!(
                "Initial raw packet capture did not start automatically (non-fatal): {}",
                e
            );
        }

        let quota = Arc::new(RwLock::new(DataUsageQuota::new(
            netscope_core::QuotaPeriod::Daily,
            5000,
        ))); // 5GB daily quota
        let active_profile = Arc::new(RwLock::new(NetworkProfile::default()));
        let latest_speedtest = Arc::new(RwLock::new(None));

        Self {
            collector,
            storage,
            storage_degraded_warning,
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
