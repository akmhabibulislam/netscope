use chrono::{DateTime, Utc};
use netscope_core::{
    AlertSeverity, BandwidthSample, DnsRecord, NetworkEvent, SecurityAlert, TimelineEventType,
};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::info;

#[derive(Clone)]
pub struct StorageManager {
    conn: Arc<Mutex<Connection>>,
    db_path: Option<PathBuf>,
}

impl StorageManager {
    pub fn new(db_path: Option<PathBuf>) -> Result<Self, anyhow::Error> {
        let path = match db_path {
            Some(p) => p,
            None => {
                let proj_dirs = directories::ProjectDirs::from("org", "netscope", "netscope")
                    .ok_or_else(|| anyhow::anyhow!("Failed to get project dirs"))?;
                let data_dir = proj_dirs.data_dir();
                std::fs::create_dir_all(data_dir)?;
                data_dir.join("netscope.sqlite")
            }
        };

        info!("Initializing NetScope SQLite database at {:?}", path);
        let conn = Connection::open(&path)?;

        // Pragmas for performance and data safety
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;",
        )?;

        let manager = Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path: Some(path),
        };

        manager.migrate()?;
        Ok(manager)
    }

    pub fn new_in_memory() -> Result<Self, anyhow::Error> {
        let conn = Connection::open_in_memory()?;
        let manager = Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path: None,
        };
        manager.migrate()?;
        Ok(manager)
    }

    pub fn is_in_memory(&self) -> bool {
        self.db_path.is_none()
    }

    pub fn db_path(&self) -> Option<&Path> {
        self.db_path.as_deref()
    }

    fn lock_conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, anyhow::Error> {
        self.conn
            .lock()
            .map_err(|e| anyhow::anyhow!("Storage mutex poisoned: {}", e))
    }

    fn migrate(&self) -> Result<(), anyhow::Error> {
        let conn = self.lock_conn()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS bandwidth_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                rx_bytes_total INTEGER NOT NULL,
                tx_bytes_total INTEGER NOT NULL,
                rx_speed_bps REAL NOT NULL,
                tx_speed_bps REAL NOT NULL,
                active_interface TEXT
            );

            CREATE TABLE IF NOT EXISTS dns_history (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                query TEXT NOT NULL,
                qtype TEXT NOT NULL,
                response TEXT,
                resolver TEXT NOT NULL,
                duration_ms INTEGER,
                process_name TEXT
            );

            CREATE TABLE IF NOT EXISTS security_alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                affected_process TEXT,
                remote_ip TEXT,
                remote_port INTEGER,
                reviewed INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS network_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                title TEXT NOT NULL,
                details TEXT NOT NULL,
                process TEXT,
                ip_or_domain TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_bw_timestamp ON bandwidth_samples(timestamp);
            CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_history(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON network_events(timestamp);",
        )?;
        Ok(())
    }

    pub fn insert_bandwidth_sample(&self, sample: &BandwidthSample) -> Result<(), anyhow::Error> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO bandwidth_samples (timestamp, rx_bytes_total, tx_bytes_total, rx_speed_bps, tx_speed_bps, active_interface)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                sample.timestamp.to_rfc3339(),
                sample.rx_bytes_total,
                sample.tx_bytes_total,
                sample.rx_speed_bps,
                sample.tx_speed_bps,
                sample.active_interface
            ],
        )?;

        // Amortized bounded retention: keep up to 10,000 samples to prevent unbounded database growth
        let _ = conn.execute(
            "DELETE FROM bandwidth_samples WHERE id < (SELECT max(id) - 10000 FROM bandwidth_samples)",
            [],
        );

        Ok(())
    }

    pub fn insert_dns_record(&self, record: &DnsRecord) -> Result<(), anyhow::Error> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO dns_history (id, timestamp, query, qtype, response, resolver, duration_ms, process_name)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                record.id,
                record.timestamp.to_rfc3339(),
                record.query,
                record.qtype,
                record.response,
                record.resolver,
                record.duration_ms,
                record.process_name
            ],
        )?;
        Ok(())
    }

    pub fn insert_alert(&self, alert: &SecurityAlert) -> Result<(), anyhow::Error> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO security_alerts (id, timestamp, severity, title, message, rule_id, affected_process, remote_ip, remote_port, reviewed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                alert.id,
                alert.timestamp.to_rfc3339(),
                alert.severity.to_string(),
                alert.title,
                alert.message,
                alert.rule_id,
                alert.affected_process,
                alert.remote_ip.map(|ip| ip.to_string()),
                alert.remote_port,
                if alert.reviewed { 1 } else { 0 }
            ],
        )?;
        Ok(())
    }

    pub fn insert_event(&self, event: &NetworkEvent) -> Result<(), anyhow::Error> {
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO network_events (id, timestamp, event_type, title, details, process, ip_or_domain)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                event.id,
                event.timestamp.to_rfc3339(),
                event.event_type.to_string(),
                event.title,
                event.details,
                event.process,
                event.ip_or_domain
            ],
        )?;
        Ok(())
    }

    pub fn get_recent_events(&self, limit: usize) -> Result<Vec<NetworkEvent>, anyhow::Error> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, event_type, title, details, process, ip_or_domain
             FROM network_events ORDER BY timestamp DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map([limit], |row| {
            let id: String = row.get(0)?;
            let ts_str: String = row.get(1)?;
            let ts = DateTime::parse_from_rfc3339(&ts_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let ev_str: String = row.get(2)?;
            let event_type = match ev_str.as_str() {
                "INTERFACE_CHANGE" => TimelineEventType::InterfaceChanged,
                "VPN_CHANGE" => TimelineEventType::VpnStateChanged,
                "CONN_OPEN" => TimelineEventType::ConnectionOpened,
                "CONN_CLOSE" => TimelineEventType::ConnectionClosed,
                "DNS_QUERY" => TimelineEventType::DnsQueried,
                "TRAFFIC_SPIKE" => TimelineEventType::TrafficSpike,
                "SECURITY_ALERT" => TimelineEventType::SecurityAlert,
                "QUOTA_WARNING" => TimelineEventType::QuotaWarning,
                _ => TimelineEventType::ProfileSwitched,
            };

            Ok(NetworkEvent {
                id,
                timestamp: ts,
                event_type,
                title: row.get(3)?,
                details: row.get(4)?,
                process: row.get(5)?,
                ip_or_domain: row.get(6)?,
            })
        })?;

        let mut events = Vec::new();
        for r in rows {
            events.push(r?);
        }
        Ok(events)
    }

    pub fn get_recent_samples(&self, limit: usize) -> Result<Vec<BandwidthSample>, anyhow::Error> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT timestamp, rx_bytes_total, tx_bytes_total, rx_speed_bps, tx_speed_bps, active_interface
             FROM bandwidth_samples ORDER BY id DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map([limit], |row| {
            let ts_str: String = row.get(0)?;
            let ts = DateTime::parse_from_rfc3339(&ts_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            Ok(BandwidthSample {
                timestamp: ts,
                rx_bytes_total: row.get(1)?,
                tx_bytes_total: row.get(2)?,
                rx_speed_bps: row.get(3)?,
                tx_speed_bps: row.get(4)?,
                active_interface: row.get(5)?,
            })
        })?;

        let mut samples = Vec::new();
        for r in rows {
            samples.push(r?);
        }
        samples.reverse();
        Ok(samples)
    }

    pub fn get_recent_alerts(&self, limit: usize) -> Result<Vec<SecurityAlert>, anyhow::Error> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, severity, title, message, rule_id, affected_process, remote_ip, remote_port, reviewed
             FROM security_alerts ORDER BY timestamp DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map([limit], |row| {
            let id: String = row.get(0)?;
            let ts_str: String = row.get(1)?;
            let ts = DateTime::parse_from_rfc3339(&ts_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let sev_str: String = row.get(2)?;
            let severity = match sev_str.as_str() {
                "Critical" => AlertSeverity::Critical,
                "High" => AlertSeverity::High,
                "Medium" => AlertSeverity::Medium,
                "Low" => AlertSeverity::Low,
                _ => AlertSeverity::Info,
            };

            let remote_ip_str: Option<String> = row.get(7)?;
            let remote_ip = remote_ip_str.and_then(|s| s.parse().ok());
            let reviewed_int: i32 = row.get(9)?;

            Ok(SecurityAlert {
                id,
                timestamp: ts,
                severity,
                title: row.get(3)?,
                message: row.get(4)?,
                rule_id: row.get(5)?,
                affected_process: row.get(6)?,
                remote_ip,
                remote_port: row.get(8)?,
                recommendations: Vec::new(),
                reviewed: reviewed_int == 1,
            })
        })?;

        let mut alerts = Vec::new();
        for r in rows {
            alerts.push(r?);
        }
        Ok(alerts)
    }

    pub fn get_recent_dns(&self, limit: usize) -> Result<Vec<DnsRecord>, anyhow::Error> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, query, qtype, response, resolver, duration_ms, process_name
             FROM dns_history ORDER BY timestamp DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map([limit], |row| {
            let id: String = row.get(0)?;
            let ts_str: String = row.get(1)?;
            let ts = DateTime::parse_from_rfc3339(&ts_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            Ok(DnsRecord {
                id,
                timestamp: ts,
                query: row.get(2)?,
                qtype: row.get(3)?,
                response: row.get(4)?,
                resolver: row.get(5)?,
                duration_ms: row.get(6)?,
                process_name: row.get(7)?,
            })
        })?;

        let mut records = Vec::new();
        for r in rows {
            records.push(r?);
        }
        Ok(records)
    }

    pub fn export_alerts_csv(&self) -> Result<String, anyhow::Error> {
        let alerts = self.get_recent_alerts(1000)?;
        let mut wtr = csv::Writer::from_writer(vec![]);
        wtr.write_record([
            "ID",
            "Timestamp",
            "Severity",
            "Title",
            "Message",
            "Rule ID",
            "Process",
            "Remote IP",
            "Remote Port",
        ])?;

        for a in alerts {
            wtr.write_record([
                a.id,
                a.timestamp.to_rfc3339(),
                a.severity.to_string(),
                a.title,
                a.message,
                a.rule_id,
                a.affected_process.unwrap_or_default(),
                a.remote_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                a.remote_port.map(|p| p.to_string()).unwrap_or_default(),
            ])?;
        }

        let data = String::from_utf8(wtr.into_inner()?)?;
        Ok(data)
    }

    pub fn export_bandwidth_csv(&self) -> Result<String, anyhow::Error> {
        let samples = self.get_recent_samples(5000)?;
        let mut wtr = csv::Writer::from_writer(vec![]);
        wtr.write_record([
            "Timestamp",
            "Rx Bytes Total",
            "Tx Bytes Total",
            "Rx Speed (bps)",
            "Tx Speed (bps)",
            "Interface",
        ])?;

        for s in samples {
            wtr.write_record([
                s.timestamp.to_rfc3339(),
                s.rx_bytes_total.to_string(),
                s.tx_bytes_total.to_string(),
                s.rx_speed_bps.to_string(),
                s.tx_speed_bps.to_string(),
                s.active_interface.unwrap_or_default(),
            ])?;
        }

        let data = String::from_utf8(wtr.into_inner()?)?;
        Ok(data)
    }

    pub fn export_html_report(&self) -> Result<String, anyhow::Error> {
        let alerts = self.get_recent_alerts(50)?;
        let events = self.get_recent_events(50)?;

        let mut html = String::from("<!DOCTYPE html><html><head><meta charset='utf-8'><title>NetScope Investigation Report</title>");
        html.push_str("<style>body{background:#0B0D11;color:#F0F3F8;font-family:sans-serif;padding:30px;} table{width:100%;border-collapse:collapse;margin-top:15px;} th,td{border:1px solid #1E2330;padding:8px 12px;text-align:left;} th{background:#12151C;color:#9AA3B5;} tr:nth-child(even){background:#12151C;}</style></head><body>");
        html.push_str("<h1>NetScope 2.0 Security & Forensic Investigation Report</h1>");
        html.push_str(&format!(
            "<p>Generated at: {} UTC</p>",
            Utc::now().to_rfc3339()
        ));

        html.push_str("<h2>Recent Security Alerts</h2><table><tr><th>Severity</th><th>Rule</th><th>Title</th><th>Message</th></tr>");
        for a in alerts {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                a.severity, a.rule_id, a.title, a.message
            ));
        }
        html.push_str("</table>");

        html.push_str("<h2>Network Event Timeline</h2><table><tr><th>Time</th><th>Type</th><th>Title</th><th>Details</th></tr>");
        for e in events {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                e.timestamp.format("%H:%M:%S"),
                e.event_type,
                e.title,
                e.details
            ));
        }
        html.push_str("</table></body></html>");

        Ok(html)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_manager_in_memory_migration_and_roundtrip() {
        let storage = StorageManager::new_in_memory().unwrap();
        assert!(storage.is_in_memory());

        let sample = BandwidthSample {
            timestamp: Utc::now(),
            rx_bytes_total: 1024,
            tx_bytes_total: 2048,
            rx_speed_bps: 8192.0,
            tx_speed_bps: 16384.0,
            active_interface: Some("eth0".to_string()),
        };

        storage.insert_bandwidth_sample(&sample).unwrap();
        let samples = storage.get_recent_samples(10).unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].active_interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn test_storage_manager_disk_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_netscope.sqlite");

        let storage = StorageManager::new(Some(db_path.clone())).unwrap();
        assert!(!storage.is_in_memory());
        assert_eq!(storage.db_path().unwrap(), db_path);

        let alert = SecurityAlert {
            id: "ALERT-1".to_string(),
            timestamp: Utc::now(),
            severity: AlertSeverity::High,
            title: "Test Alert".to_string(),
            message: "Test Message".to_string(),
            rule_id: "RULE_TEST".to_string(),
            affected_process: Some("curl".to_string()),
            remote_ip: None,
            remote_port: Some(80),
            recommendations: vec![],
            reviewed: false,
        };

        storage.insert_alert(&alert).unwrap();
        let alerts = storage.get_recent_alerts(5).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].id, "ALERT-1");
    }
}
