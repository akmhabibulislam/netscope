use chrono::Utc;
use netscope_core::{AlertSeverity, BandwidthSample, ConnectionState, NetworkConnection, Protocol};
use netscope_network::collector::NetworkCollector;
use netscope_security::SecurityRuleEngine;
use netscope_storage::StorageManager;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_security_rules_evaluation() {
    let mut engine = SecurityRuleEngine::new(vec![], vec![]);

    let suspicious_conn = NetworkConnection {
        id: "test-conn-1".to_string(),
        protocol: Protocol::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        local_port: 4444,
        remote_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        remote_port: 0,
        state: ConnectionState::Listen,
        inode: 12345,
        process: None,
        reverse_dns: None,
        country: None,
        city: None,
        asn: None,
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    };

    let alerts = engine.evaluate_connections(&[suspicious_conn]);
    assert!(
        !alerts.is_empty(),
        "Suspicious listening port 4444 should generate an alert"
    );
    assert_eq!(alerts[0].severity, AlertSeverity::High);
    assert_eq!(alerts[0].rule_id, "RULE_SUSPICIOUS_PORT");
}

#[test]
fn test_bandwidth_spike_alert() {
    let mut engine = SecurityRuleEngine::new(vec![], vec![]);
    let sample = BandwidthSample {
        timestamp: Utc::now(),
        rx_bytes_total: 1000,
        tx_bytes_total: 1000,
        rx_speed_bps: 10_000_000.0,
        tx_speed_bps: 250_000_000.0, // 250 Mbps > 200 Mbps threshold
        active_interface: Some("wlan0".to_string()),
    };

    let alert = engine.evaluate_bandwidth(&sample);
    assert!(alert.is_some(), "Bandwidth burst should trigger an alert");
    assert_eq!(alert.unwrap().rule_id, "RULE_BANDWIDTH_BURST");
}

#[test]
fn test_storage_roundtrip() {
    let storage = StorageManager::new_in_memory().expect("In-memory SQLite initialization");
    let sample = BandwidthSample {
        timestamp: Utc::now(),
        rx_bytes_total: 54321,
        tx_bytes_total: 12345,
        rx_speed_bps: 102400.0,
        tx_speed_bps: 204800.0,
        active_interface: Some("eth0".to_string()),
    };

    storage
        .insert_bandwidth_sample(&sample)
        .expect("Insert sample");
    let recents = storage.get_recent_samples(10).expect("Query samples");
    assert_eq!(recents.len(), 1);
    assert_eq!(recents[0].rx_bytes_total, 54321);
    assert_eq!(recents[0].active_interface.as_deref(), Some("eth0"));
}

#[tokio::test]
async fn test_collector_live_polling() {
    let collector = NetworkCollector::new();
    let interfaces = collector.poll_interfaces().await;
    assert!(
        !interfaces.is_empty(),
        "Linux systems must have at least loopback interface"
    );

    let conns = collector.poll_connections().await;
    println!(
        "Discovered {} active Linux network connections",
        conns.len()
    );
}
