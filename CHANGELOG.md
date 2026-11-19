# Changelog

All notable changes to **NetScope** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] - 2026-11-20

### 🚀 Added
- **Live Inbound & Outbound Packet Sniffer**:
  - Real-time kernel packet capture engine supporting `AF_PACKET` raw sockets with automatic fallback to high-frequency socket observing.
  - Live inspection stream with protocol breakdown (TCP, UDP, ICMP, DNS, TLS).
  - Explicit visual directional badges: `INBOUND` (green) and `OUTBOUND` (red).
- **Cairo Waveform Bandwidth Canvas**:
  - High-performance, GPU-accelerated Cairo graph rendering rolling 60-second RX and TX spline waveforms directly on the dashboard.
- **Connection Forensics Drawer**:
  - Deep forensic modal inspecting socket details, remote IP reverse lookups, process path, and network socket metadata.
  - One-click active connection drop via Linux socket termination (`ss -K`).
- **Wi-Fi & Wireless RF Analyzer**:
  - Detailed live telemetry for wireless interfaces (`wlan0`): SSID, BSSID, RSSI (dBm), channel frequency (2.4/5/6 GHz), and bitrate.
- **Built-in Speedtest Benchmark**:
  - Multi-threaded HTTP latency and download throughput testing directly from GUI and CLI.
- **Dedicated CLI Companion**:
  - Standalone `netscope-cli` binary with rich formatted tables for headless servers and terminal diagnostics (`sniff`, `status`, `connections`, `processes`, `diagnostics`, `wifi`, `speedtest`, `alerts`, `kill`).
- **Comprehensive Packaging**:
  - Native Arch Linux / CachyOS package recipe (`packaging/arch/PKGBUILD`).
  - Standalone, portable universal installer script (`install.sh`).
  - Flatpak manifest (`packaging/flatpak/org.netscope.NetScope.yml`).

### 🎨 Improved
- Complete UI/UX redesign adopting modern Libadwaita dark theme principles with emerald/blue accenting.
- Command Palette (`Ctrl+K`) for fast keyboard navigation across all views and actions.
- Optimized process socket attribution via `/proc/<pid>/fd/` inode resolution with caching.

### 🔒 Security
- Offline IoC matching engine for local C2 and malicious destination flagging without telemetry leakage.
- Behavioral anomaly heuristics for public listening ports, reverse shell patterns, and anomalous transfer spikes.

---

## [0.1.0] - Initial Release

- Core GTK4 desktop layout with Libadwaita integration.
- Linux `/proc/net` interface traffic monitoring and bandwidth calculation.
- Basic TCP and UDP connection table.
- System DNS resolution tester and query history.
- SQLite WAL historical storage engine.
