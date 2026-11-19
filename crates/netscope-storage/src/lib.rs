use chrono::{DateTime, Utc};
use netscope_core::{AlertSeverity, BandwidthSample, DnsRecord, SecurityAlert};
use rusqlite::{params, Connection};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{error, info};

#[derive(Clone)]
pub struct StorageManager {
    conn: Arc<Mutex<Connection>>,
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
        let conn = Connection::open(path)?;

        // Pragmas for performance and data safety
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;"
        )?;

        let manager = Self {
            conn: Arc::new(Mutex::new(conn)),
        };

        manager.migrate()?;
        Ok(manager)
    }

    pub fn new_in_memory() -> Result<Self, anyhow::Error> {
        let conn = Connection::open_in_memory()?;
        let manager = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        manager.migrate()?;
        Ok(manager)
    }

    fn migrate(&self) -> Result<(), anyhow::Error> {
        let conn = self.conn.lock().unwrap();
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
                duration_ms INTEGER
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

            CREATE INDEX IF NOT EXISTS idx_bw_timestamp ON bandwidth_samples(timestamp);
            CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_history(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp);",
        )?;
        Ok(())
    }

    pub fn insert_bandwidth_sample(&self, sample: &BandwidthSample) -> Result<(), anyhow::Error> {
        let conn = self.conn.lock().unwrap();
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
        Ok(())
    }

    pub fn insert_dns_record(&self, record: &DnsRecord) -> Result<(), anyhow::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO dns_history (id, timestamp, query, qtype, response, resolver, duration_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.id,
                record.timestamp.to_rfc3339(),
                record.query,
                record.qtype,
                record.response,
                record.resolver,
                record.duration_ms
            ],
        )?;
        Ok(())
    }

    pub fn insert_alert(&self, alert: &SecurityAlert) -> Result<(), anyhow::Error> {
        let conn = self.conn.lock().unwrap();
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

    pub fn get_recent_samples(&self, limit: usize) -> Result<Vec<BandwidthSample>, anyhow::Error> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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
                "INFO" => AlertSeverity::Info,
                "LOW" => AlertSeverity::Low,
                "MEDIUM" => AlertSeverity::Medium,
                "HIGH" => AlertSeverity::High,
                "CRITICAL" => AlertSeverity::Critical,
                _ => AlertSeverity::Info,
            };
            let title: String = row.get(3)?;
            let message: String = row.get(4)?;
            let rule_id: String = row.get(5)?;
            let affected_process: Option<String> = row.get(6)?;
            let remote_ip_str: Option<String> = row.get(7)?;
            let remote_ip = remote_ip_str.and_then(|s| s.parse().ok());
            let remote_port: Option<u16> = row.get(8)?;
            let reviewed: bool = row.get::<_, i32>(9)? != 0;

            Ok(SecurityAlert {
                id,
                timestamp: ts,
                severity,
                title,
                message,
                rule_id,
                affected_process,
                remote_ip,
                remote_port,
                recommendations: Vec::new(),
                reviewed,
            })
        })?;

        let mut alerts = Vec::new();
        for r in rows {
            alerts.push(r?);
        }
        Ok(alerts)
    }

    pub fn export_alerts_csv(&self) -> Result<String, anyhow::Error> {
        let alerts = self.get_recent_alerts(1000)?;
        let mut wtr = csv::Writer::from_writer(vec![]);
        wtr.write_record(&["ID", "Timestamp", "Severity", "Title", "Message", "Rule", "Process", "Remote IP", "Remote Port", "Reviewed"])?;
        for a in alerts {
            wtr.write_record(&[
                a.id,
                a.timestamp.to_rfc3339(),
                a.severity.to_string(),
                a.title,
                a.message,
                a.rule_id,
                a.affected_process.unwrap_or_default(),
                a.remote_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                a.remote_port.map(|p| p.to_string()).unwrap_or_default(),
                a.reviewed.to_string(),
            ])?;
        }
        let data = String::from_utf8(wtr.into_inner()?)?;
        Ok(data)
    }
}
