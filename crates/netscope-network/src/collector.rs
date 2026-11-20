use crate::connection::ConnectionScanner;
use crate::interfaces::InterfaceManager;
use chrono::Utc;
use netscope_core::{BandwidthSample, NetworkConnection, NetworkInterface};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct NetworkCollector {
    interface_manager: Arc<RwLock<InterfaceManager>>,
    connection_scanner: Arc<RwLock<ConnectionScanner>>,
    history_samples: Arc<RwLock<Vec<BandwidthSample>>>,
}

impl NetworkCollector {
    pub fn new() -> Self {
        Self {
            interface_manager: Arc::new(RwLock::new(InterfaceManager::new())),
            connection_scanner: Arc::new(RwLock::new(ConnectionScanner::new())),
            history_samples: Arc::new(RwLock::new(Vec::with_capacity(3600))),
        }
    }

    pub async fn poll_interfaces(&self) -> Vec<NetworkInterface> {
        let mut mgr = self.interface_manager.write().await;
        mgr.discover_interfaces()
    }

    pub async fn poll_connections(&self) -> Vec<NetworkConnection> {
        let mut scanner = self.connection_scanner.write().await;
        scanner.scan_connections()
    }

    pub async fn collect_bandwidth_sample(&self) -> BandwidthSample {
        self.collect_bandwidth_sample_for(None).await
    }

    pub async fn collect_bandwidth_sample_for(
        &self,
        specific_iface: Option<&str>,
    ) -> BandwidthSample {
        let interfaces = self.poll_interfaces().await;
        let mut total_rx = 0u64;
        let mut total_tx = 0u64;
        let mut total_rx_speed = 0.0f64;
        let mut total_tx_speed = 0.0f64;
        let mut active_iface = None;

        for iface in &interfaces {
            if let Some(target) = specific_iface {
                if iface.name != target {
                    continue;
                }
            } else if iface.is_loopback {
                continue;
            }

            total_rx += iface.stats.rx_bytes;
            total_tx += iface.stats.tx_bytes;
            total_rx_speed += iface.rx_speed_bps;
            total_tx_speed += iface.tx_speed_bps;

            if active_iface.is_none() {
                active_iface = Some(iface.name.clone());
            }
        }

        if active_iface.is_none() {
            active_iface = interfaces
                .iter()
                .find(|i| !i.is_loopback && i.is_up)
                .map(|i| i.name.clone());
        }

        let sample = BandwidthSample {
            timestamp: Utc::now(),
            rx_bytes_total: total_rx,
            tx_bytes_total: total_tx,
            rx_speed_bps: total_rx_speed,
            tx_speed_bps: total_tx_speed,
            active_interface: active_iface,
        };

        let mut history = self.history_samples.write().await;
        if history.len() >= 3600 {
            history.remove(0);
        }
        history.push(sample.clone());

        sample
    }

    pub async fn get_samples(&self, limit: usize) -> Vec<BandwidthSample> {
        let history = self.history_samples.read().await;
        if history.len() <= limit {
            history.clone()
        } else {
            history[history.len() - limit..].to_vec()
        }
    }
}

impl Default for NetworkCollector {
    fn default() -> Self {
        Self::new()
    }
}
