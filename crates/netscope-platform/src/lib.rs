use netscope_core::SecurityAlert;
use notify_rust::Notification;
use tracing::warn;

pub struct DesktopNotifier;

impl DesktopNotifier {
    pub fn send_alert_notification(alert: &SecurityAlert) {
        let summary = format!("[NetScope Alert] {}", alert.title);
        let body = format!("Severity: {}\n{}", alert.severity, alert.message);

        let res = Notification::new()
            .appname("NetScope")
            .summary(&summary)
            .body(&body)
            .icon("network-wireless")
            .timeout(5000)
            .show();

        if let Err(e) = res {
            warn!("Failed to dispatch desktop notification: {}", e);
        }
    }
}
