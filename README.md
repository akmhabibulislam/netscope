# NetScope

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-brightgreen.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-Linux-orange.svg)](https://kernel.org/)

**NetScope** is a high-performance, cross-distribution Linux network intelligence and diagnostic desktop application written in Rust, GTK4, and Libadwaita. It delivers deep, real-time observability into network interfaces, active sockets, per-process socket attribution, DNS resolution, system routing, and anomaly detection—operating locally and privacy-focused by default without mandatory root privileges.

---

## Key Features

- **Real-Time Network Dashboard**: Live download/upload speed counters from portable `/sys/class/net/<iface>/statistics/`, active interface autodetection, IPv4/IPv6 addresses, MAC address, and MTU.
- **Active Connection Intelligence**: Full enumeration of active TCP and UDP sockets across IPv4 and IPv6 from `/proc/net/tcp{,6}` and `/proc/net/udp{,6}`, connection states (`ESTABLISHED`, `LISTEN`, `TIME_WAIT`), and remote destinations.
- **Per-Process Socket Attribution**: Seamless mapping of socket inodes to running processes via `/proc/<pid>/fd/` without requiring root permissions.
- **DNS Diagnostics & History**: System resolver discovery (`/etc/resolv.conf`, `systemd-resolved`), live multi-record resolution tests (A, AAAA, MX, TXT) with response timing.
- **Security & Anomaly Detection**: Transparent heuristic rule engine alerting on high-risk listening ports, communication with reserved/documentation IP spaces, newly observed network processes, and outbound bandwidth spikes.
- **Network Diagnostics Suite**: Built-in ping latency & packet loss tests, TCP port connectivity tests, and kernel routing table inspector.
- **Historical Telemetry Persistence**: High-speed, batched SQLite WAL storage for bandwidth samples, DNS queries, and security alerts with CSV export capabilities.
- **Dual-Interface UX**: A modern, dark-themed native GTK4/Libadwaita GUI alongside a full-featured CLI companion tool (`netscope`).

---

## Architecture & Modular Workspace

NetScope is structured into focused crates:

```
netscope/
├── crates/
│   ├── netscope-core/       # Core types, events, metrics, and models
│   ├── netscope-network/    # Interface discovery, socket parsing, bandwidth tracking
│   ├── netscope-process/    # /proc parsing, fd inode resolution, PID metadata
│   ├── netscope-dns/        # System resolver inspection, async DNS resolution
│   ├── netscope-security/   # Threat heuristic rules, anomaly detection
│   ├── netscope-storage/    # SQLite WAL database and CSV reporting
│   ├── netscope-platform/   # Freedesktop notifications and system integration
│   └── netscope-cli/        # Terminal CLI companion
├── src/                     # Native GTK4 desktop GUI
├── resources/               # SVG icons, CSS styling, desktop files
├── packaging/               # Arch PKGBUILD, Flatpak manifest, AppImage spec
└── tests/                   # Integration and rule engine tests
```

---

## Installation & Building

### Prerequisites

Ensure you have GTK4, Libadwaita, SQLite, and a standard Rust toolchain installed:

- **Arch Linux / CachyOS / EndeavourOS**:
  ```bash
  sudo pacman -S rust cargo gtk4 libadwaita sqlite iproute2
  ```
- **Fedora / RHEL**:
  ```bash
  sudo dnf install rust cargo gtk4-devel libadwaita-devel sqlite-devel
  ```
- **Ubuntu / Debian**:
  ```bash
  sudo apt install cargo rustc libgtk-4-dev libadwaita-1-dev libsqlite3-dev
  ```

### Build from Source

```bash
# Clone the repository
git clone https://github.com/netscope/netscope.git
cd netscope

# Build workspace
cargo build --release

# Run the CLI Companion
./target/release/netscope --help

# Run the Desktop GUI
./target/release/netscope-gui
```

---

## CLI Companion Examples

```bash
# General network summary
netscope status

# View detected interfaces and byte counters
netscope interfaces

# Inspect active TCP and UDP sockets
netscope connections

# List processes with open sockets
netscope processes

# Query DNS
netscope dns --domain archlinux.org --qtype A

# Run network diagnostics
netscope diagnostics --ping 1.1.1.1
netscope diagnostics --tcp google.com --port 443
netscope diagnostics --routes

# Inspect security alerts
netscope alerts

# Export historical data
netscope export --format csv
```

---

## Privacy & Security Model

1. **Local-First**: No data is ever transmitted to remote servers by default.
2. **No Root Requirement**: Standard telemetry, socket reading, and process resolution leverage unprivileged Linux `/proc` and `/sys` interfaces.
3. **Opt-in Enrichment**: External IP geolocation and public IP discovery are strictly disabled by default and require explicit user opt-in in settings.
4. **Transparent Rules**: Security detections do not rely on proprietary or closed threat feeds.

---

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE) at your option.
