# NetScope 2.0 Features & Functional Specifications

## 1. Overview
NetScope 2.0 introduces a redesigned desktop user interface alongside comprehensive network telemetry and diagnostic features:

- **Unified Navigation & Modern Dark Aesthetic**: Inspired by Linear, Raycast, and Vercel. High-density typography, subtle elevation borders, and status-colored semantic micro-badges.
- **Global Command Palette (`Ctrl+K`)**: Keyboard-driven navigation and action palette allowing instant navigation across all views.
- **Connection Inspector Drawer**: Deep socket forensics (local & remote endpoints, PID, executable path, UID/username, socket inode, reverse DNS) directly in an interactive modal.
- **AF_PACKET / Raw Stream Inspector**: Live capture and directional tagging of every inbound and outbound packet.
- **Data Usage Quotas & Allowances**: Track daily/monthly bandwidth consumption against configured limits.
- **Internet Speed & Throughput Benchmark**: Measure ping latency, jitter, and multi-megabyte download and upload transfer rates against global edge endpoints.
- **IP & Domain Forensic Investigation**: Automatic target classification (RFC 1918 private vs public), reverse DNS resolution, network ASN organization, and offline IoC threat intelligence.
- **Network Activity Timeline**: Chronological event recorder capturing interface state changes, socket lifecycles, and security alerts.
- **Wi-Fi & RF Spectrum Analytics**: Signal RSSI (dBm), Link Quality (%), Frequency (GHz), and TX Bitrate (Mbps).
- **Security Center & Anomaly Detection**: Behavioral rule engine with offline IoC matching and instant socket termination.
