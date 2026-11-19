# 🌐 NetScope — Linux Network Intelligence Application

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2024%20Stable-brightgreen.svg)](https://www.rust-lang.org/)
[![GUI](https://img.shields.io/badge/GUI-GTK4%20%2F%20Libadwaita-purple.svg)](https://gtk.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://kernel.org/)
[![Status](https://img.shields.io/badge/Build-Passing-success.svg)]()

**NetScope** is a high-performance, cross-distribution Linux network intelligence, live packet sniffer, and threat detection desktop application written in **Rust**, **GTK4**, and **Libadwaita**. It provides deep, real-time visibility into all inbound and outbound network data streams, active sockets, per-process socket attribution, wireless RF metrics, system DNS resolution, and anomalous activity—designed with **privacy-by-default** principles and requiring no mandatory root access.

---

## ✨ Key Features & Capabilities

### 📡 1. Live Inbound & Outbound Packet Sniffer
- **Complete Data Stream Inspection**: Real-time packet capture stream detailing traffic entering and leaving your system.
- **Directional Tagging**: Clearly distinguishes `INBOUND` from `OUTBOUND` traffic with dedicated badges.
- **Protocol & Payload Dissection**: Identifies TCP, UDP, ICMP, DNS queries, and TLS/HTTPS application payloads with byte-exact length counters.
- **Dual-Engine Architecture**: Employs Linux kernel `AF_PACKET` raw sockets when available, with automatic unprivileged fallback to high-frequency socket observing.

### 📈 2. Animated Bandwidth Waveform Graph
- Embedded, GPU-accelerated **Cairo canvas graph** directly on the Dashboard.
- **Dual-channel spline waveforms**: Smooth Download (RX) and Upload (TX) curves over a 60-second rolling window.
- Real-time adaptive peak-scaling and throughput metric overlays.

### 🔍 3. Connection Forensics & Socket Termination
- **Deep Connection Inspection**: Detailed view showing socket state, PID attribution, binary path, address family, and protocol.
- **1-Click Socket Drop**: Terminate unwanted or rogue TCP sockets directly from the GUI or CLI via Linux `ss -K`.
- **IP Firewall Blocking**: Integrated Linux netfilter interface to blackhole suspicious destinations.

### 📶 4. Wi-Fi & Wireless RF Spectrum Analyzer
- Dedicated wireless tab displaying real-time metrics for associated wireless interfaces (`wlan0`):
  - **Connected SSID** & **BSSID / Access Point MAC**
  - **Signal RSSI (dBm)** with percentage Link Quality estimation
  - **Channel Frequency (GHz)**: 2.4 GHz, 5 GHz, or 6 GHz Wi-Fi 6E/7
  - **Transmit Bitrate (Mbps)**

### 🛡️ 5. Anomaly Detection & Offline Threat Intelligence
- **Offline IoC Matching**: Automatically cross-references remote IP addresses against local, privacy-preserving threat intelligence feeds (known C2 nodes, Tor exit relays) without sending telemetry to external parties.
- **Behavioral Security Heuristics**:
  - Flags unexpected listening sockets on public addresses (reverse shell ports like 4444, 23, 31337).
  - Outbound data spikes (> 200 Mbps).
  - High-frequency socket opening by single binaries.
  - Reserved / documentation address routing anomalies.

### ⚙️ 6. Per-Process Network Attribution
- Resolves open sockets to executing Linux processes, PIDs, and binaries via `/proc/<pid>/fd/` socket inode linking.
- Aggregates sockets by process name, showing open socket counts, protocols, and executable paths.

### 🧪 7. Diagnostics, Speedtest & DNS History
- Built-in multi-threaded HTTP latency and download throughput benchmark.
- Multi-record DNS querying (A, AAAA, MX, TXT) with millisecond-resolution response timing.
- Ping latency (min/avg/max) and packet loss tester.
- TCP port reachability checks and kernel routing tables (`/proc/net/route`) inspection.

---

## 📦 Installation Tutorial

NetScope can be installed using pre-built distribution packages, the native desktop installer script, or built directly from source.

### 🐧 Method 1: Arch Linux / CachyOS / EndeavourOS / Manjaro (`pacman`)

If you are on an Arch-based distribution, install the ready-to-use pacman package:

```bash
# Build the package (or use pre-built package in packaging/arch/)
cd packaging/arch
makepkg -si
```

Or install directly with `pacman`:
```bash
sudo pacman -U packaging/arch/netscope-0.2.0-1-x86_64.pkg.tar.zst
```

This installs:
- `/usr/bin/netscope` (GUI launcher symlink)
- `/usr/bin/netscope-gui` (Main GTK4 desktop application)
- `/usr/bin/netscope-cli` (Command-line companion tool)
- `/usr/share/applications/netscope.desktop` (XDG desktop integration)
- `/usr/share/icons/hicolor/scalable/apps/netscope.svg` (Application icon)

---

### 💻 Method 2: Universal Desktop Installer Script (`install.sh`)

NetScope includes an installer script that installs the binaries, desktop menu entry, and icon for your current user without needing root privileges.

```bash
# Clone the repository
git clone https://github.com/akmhabibulislam/netscope.git
cd netscope

# Build release binaries
cargo build --release

# Run the installer (installs to ~/.local/bin and ~/.local/share/applications)
./install.sh
```

To install system-wide to `/usr/local`:
```bash
sudo PREFIX=/usr/local ./install.sh
```

---

### 🛠️ Method 3: Building from Source

#### Step 1: Install System Build Dependencies

- **Arch Linux / CachyOS / Manjaro**:
  ```bash
  sudo pacman -S rust cargo gtk4 libadwaita sqlite iproute2 libcap pkgconf
  ```
- **Fedora / RHEL**:
  ```bash
  sudo dnf install rust cargo gtk4-devel libadwaita-devel sqlite-devel libcap-devel pkgconf
  ```
- **Ubuntu / Debian / Linux Mint / Pop!_OS**:
  ```bash
  sudo apt install cargo rustc libgtk-4-dev libadwaita-1-dev libsqlite3-dev libcap2-bin pkg-config
  ```

#### Step 2: Compile the Workspace

```bash
cargo build --release
```

Compiled binaries will be available in `target/release/`:
- `target/release/netscope` — Desktop application
- `target/release/netscope-cli` — Terminal CLI companion

---

### 🔐 Optional: Packet Sniffer Raw Sockets Capability

NetScope functions completely out-of-the-box without root privileges. To enable kernel-level raw packet sniffing (`AF_PACKET`) without running the app as `root`, grant `cap_net_raw` and `cap_net_admin` to the binary:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip target/release/netscope
# or for installed binary:
sudo setcap cap_net_raw,cap_net_admin+eip ~/.local/bin/netscope-gui
```

---

## 🚀 Running NetScope

### Desktop GUI
Launch the graphical interface from your application launcher (App Menu / GNOME / KDE / Rofi / Wofi) or run:
```bash
netscope
```

### CLI Companion (`netscope-cli`)
The CLI companion shares the same underlying Rust network intelligence engine:

```bash
# Network status summary and active interface
netscope-cli status

# Stream live inbound & outbound packets
netscope-cli sniff --count 15

# Inspect Wi-Fi link parameters (SSID, RSSI, Frequency, Bitrate)
netscope-cli wifi

# Run internet throughput benchmark
netscope-cli speedtest

# Forensically investigate an IP or domain
netscope-cli investigate --target 1.1.1.1

# Inspect active TCP/UDP connections
netscope-cli connections

# List processes actively using the network
netscope-cli processes

# Query DNS through system resolvers
netscope-cli dns --domain archlinux.org --qtype A

# Run network diagnostics
netscope-cli diagnostics --ping 1.1.1.1
netscope-cli diagnostics --tcp 1.1.1.1 --port 443
netscope-cli diagnostics --routes

# Inspect security & threat alerts
netscope-cli alerts

# Drop an active socket (requires appropriate capabilities)
netscope-cli kill --src 192.168.1.10:49152 --dst 1.1.1.1:443

# Export historical database records to CSV
netscope-cli export --format csv
```

---

## 🏛️ Architecture

NetScope is structured into decoupled, maintainable Rust crates:

```
netscope/
├── crates/
│   ├── netscope-core/       # Core types, events, metrics, sniffer definitions
│   ├── netscope-network/    # AF_PACKET sniffer, bandwidth tracking, /proc/net, Wi-Fi, speedtest
│   ├── netscope-process/    # Linux /proc/<pid>/fd/ socket inode resolution to PID & exe
│   ├── netscope-dns/        # System resolver configuration & async DNS resolution
│   ├── netscope-security/   # Heuristic rules & offline IoC threat intelligence
│   ├── netscope-storage/    # SQLite WAL database for persistent historical telemetry
│   ├── netscope-platform/   # Freedesktop desktop notifications and OS integration
│   └── netscope-cli/        # Terminal CLI companion tool (netscope-cli)
├── src/                     # Native GTK4 / Libadwaita desktop application
│   ├── app.rs               # Application UI layout, navigation, and reactive loops
│   ├── graph.rs             # Custom Cairo 60-second animated bandwidth graph
│   └── main.rs              # Application entrypoint
├── resources/               # App icons, SVG assets, and modern dark CSS styling
├── packaging/               # Arch PKGBUILD, Flatpak manifest, AppImage specs
└── tests/                   # Integration tests and synthetic security rule fixtures
```

---

## 🔒 Security & Privacy Model

1. **Strictly Local-First**: No background telemetry, metrics, or diagnostic data is ever transmitted over the network.
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

## 📜 License

Distributed under the [MIT License](LICENSE).
