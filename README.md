# NetScope — Linux Network Intelligence Application

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-brightgreen.svg)](https://www.rust-lang.org/)
[![GTK4](https://img.shields.io/badge/GUI-GTK4%20%2F%20Libadwaita-purple.svg)](https://gtk.org/)
[![Platform](https://img.shields.io/badge/platform-Linux-orange.svg)](https://kernel.org/)
[![Status](https://img.shields.io/badge/build-passing-success.svg)]()

**NetScope** is a high-performance, cross-distribution Linux network intelligence, live packet sniffer, and threat detection desktop application written in **Rust**, **GTK4**, and **Libadwaita**. It provides deep, real-time visibility into all inbound and outbound network data streams, active sockets, per-process socket attribution, wireless RF metrics, system DNS resolution, and anomalous activity—designed with **privacy-by-default** principles and requiring no mandatory root access.

---

## 🌟 Major Highlights & Capabilities

### 1. 📡 Live Inbound & Outbound Data Sniffer (`Live Packets`)
- **Complete In/Out Data Inspection**: Real-time packet capture stream showing every piece of traffic entering and leaving your laptop or machine.
- **Directional Tagging**: Instantly distinguishes `INBOUND` (green) from `OUTBOUND` (red) traffic.
- **Protocol & Payload Dissection**: Identifies TCP, UDP, ICMP, DNS queries, and TLS/HTTPS application data payloads with byte-exact length counters.
- **Dual-Engine Architecture**: Uses Linux kernel `AF_PACKET` raw sockets when available, with automatic unprivileged fallback to high-frequency socket observing.

### 2. 📊 Live Animated Bandwidth Waveform Graph
- Embedded, GPU-accelerated **Cairo canvas graph** directly on the Dashboard.
- **Dual-channel spline waveforms**: **Emerald Green** curve for Download (RX) and **Accent Blue** curve for Upload (TX) over a 60-second rolling window.
- Real-time adaptive peak-scaling and throughput metric overlays.

### 3. 📶 Wi-Fi & Wireless RF Spectrum Analyzer
- Dedicated wireless tab displaying real-time metrics for associated wireless interfaces (`wlan0`):
  - **Connected SSID** & **BSSID / Access Point MAC**
  - **Signal RSSI (dBm)** with percentage Link Quality estimation
  - **Channel Frequency (GHz)**: 2.4 GHz, 5 GHz, or 6 GHz Wi-Fi 6E/7
  - **Transmit Bitrate (Mbps)**

### 4. 🛡️ Network Defense & Connection Termination (`Drop`)
- **Active Socket Termination**: Every discovered connection row in the GUI features a 1-click **"Drop"** action that terminates unwanted TCP sockets via Linux `ss -K`.
- **IP Firewall Blocking**: Integrated Linux netfilter interface to blackhole suspicious destinations.

### 5. 🔍 Anomaly Detection & Offline Threat Intelligence
- **Offline IoC Matching**: Automatically cross-references remote IP addresses against local, privacy-preserving threat intelligence feeds (known C2 nodes, Tor exit relays) without sending telemetry to external parties.
- **Behavioral Security Heuristics**:
  - Flags unexpected listening sockets on public addresses (e.g., reverse shell ports like 4444, 23, 31337).
  - Outbound data spikes (> 200 Mbps).
  - High-frequency socket opening by single binaries.
  - Reserved / documentation address routing anomalies.

### 6. 🔎 Per-Process Network Attribution
- Resolves open sockets to executing Linux processes, PIDs, and binaries via `/proc/<pid>/fd/` socket inode linking.
- Aggregates sockets by process name, showing open socket counts, protocols, and executable paths.

### 7. 🧪 Diagnostics & DNS History
- Multi-record DNS querying (A, AAAA, MX, TXT) with millisecond-resolution response timing.
- Built-in ping latency (min/avg/max) and packet loss tester.
- TCP port reachability checks.
- Direct visualization of kernel routing tables (`/proc/net/route`).

---

## 🏗️ Modular Workspace Architecture

NetScope is organized into decoupled, modular crates:

```
netscope/
├── crates/
│   ├── netscope-core/       # Core domain types, events, metrics, sniffer definitions
│   ├── netscope-network/    # AF_PACKET sniffer, bandwidth tracking, /proc/net, Wi-Fi, firewall
│   ├── netscope-process/    # Linux /proc/<pid>/fd/ socket inode resolution to PID & exe
│   ├── netscope-dns/        # System resolver configuration & async DNS resolution
│   ├── netscope-security/   # Heuristic rules & offline IoC threat intelligence
│   ├── netscope-storage/    # SQLite WAL database for persistent historical telemetry
│   ├── netscope-platform/   # Freedesktop desktop notifications and OS integration
│   └── netscope-cli/        # Terminal CLI companion tool (`netscope`)
├── src/                     # Native GTK4 / Libadwaita desktop application
│   ├── app.rs               # Application UI layout, navigation, and reactive loops
│   ├── graph.rs             # Custom Cairo 60-second animated bandwidth graph
│   └── main.rs              # Application entrypoint
├── resources/               # App icons, SVG assets, and modern dark CSS styling
├── packaging/               # Arch PKGBUILD, Flatpak manifest, AppImage specs
└── tests/                   # Integration tests and synthetic security rule fixtures
```

---

## 🚀 Installation & Building

### 1. System Dependencies

- **Arch Linux / CachyOS / EndeavourOS / Manjaro**:
  ```bash
  sudo pacman -S rust cargo gtk4 libadwaita sqlite iproute2
  ```
- **Fedora / RHEL / CentOS**:
  ```bash
  sudo dnf install rust cargo gtk4-devel libadwaita-devel sqlite-devel
  ```
- **Ubuntu / Debian / Linux Mint / Pop!_OS**:
  ```bash
  sudo apt install cargo rustc libgtk-4-dev libadwaita-1-dev libsqlite3-dev
  ```

### 2. Build from Source

```bash
# Clone the repository
git clone https://github.com/netscope/netscope.git
cd netscope

# Build workspace in release mode
cargo build --release
```

The resulting binaries will be available under:
- `target/release/netscope` (Desktop GUI)
- `target/release/netscope-cli` (Terminal CLI Companion)

---

## 🖥️ Running the Application

### Desktop GUI
Launch the full graphical interface:
```bash
cargo run --bin netscope
```
*(Or directly run `./target/release/netscope`)*

### Terminal Companion CLI (`netscope`)
The CLI companion shares the same underlying engine:

```bash
# Display general status and live active interface
cargo run -p netscope-cli -- status

# Stream live inbound & outbound packets (e.g. capture 10 packets)
cargo run -p netscope-cli -- sniff --count 10

# Inspect Wi-Fi RF parameters (SSID, RSSI, Frequency, Bitrate)
cargo run -p netscope-cli -- wifi

# List detected network interfaces & byte counters
cargo run -p netscope-cli -- interfaces

# Inspect active TCP/UDP connections
cargo run -p netscope-cli -- connections

# List processes actively using the network
cargo run -p netscope-cli -- processes

# Query DNS through system resolvers
cargo run -p netscope-cli -- dns --domain archlinux.org --qtype A

# Test network diagnostics
cargo run -p netscope-cli -- diagnostics --ping 1.1.1.1
cargo run -p netscope-cli -- diagnostics --tcp google.com --port 443
cargo run -p netscope-cli -- diagnostics --routes

# Inspect security & threat alerts
cargo run -p netscope-cli -- alerts

# Drop an active socket (requires appropriate capabilities)
cargo run -p netscope-cli -- kill --src 192.168.10.177:49152 --dst 1.1.1.1:443

# Export historical database records to CSV
cargo run -p netscope-cli -- export --format csv
```

---

## 🔒 Security & Privacy Model

1. **Strictly Local-First**: No background telemetry, metrics, or diagnostic data is ever sent over the internet.
2. **Offline Threat Intel**: IoC checking uses local lists rather than querying external APIs with your network destinations.
3. **Unprivileged Operation**: The entire core application functions smoothly as a regular unprivileged desktop user without `sudo`.
4. **Safe Privileged Actions**: Potentially disruptive actions (such as dropping sockets or modifying netfilter rules) are clearly isolated and require explicit confirmation.

---

## 🧪 Testing

Run the automated test suite across all workspace crates:

```bash
cargo test --workspace
```

---

## 📄 License

Dual-licensed under either of:
- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
