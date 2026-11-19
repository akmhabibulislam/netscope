# NetScope 2.0 — Codebase Audit & Feature Verification Matrix

**Audit Date**: November 20, 2026  
**Auditor**: NetScope Principal Systems & Cybersecurity Architecture Team  
**Scope**: All crates in workspace (`netscope-core`, `netscope-network`, `netscope-process`, `netscope-dns`, `netscope-security`, `netscope-storage`, `netscope-platform`, `netscope-cli`), frontend desktop application (`src/app.rs`, `src/graph.rs`), packaging scripts, build targets, and unit/integration test suites.

---

## 1. Feature Verification Matrix

| Documented Feature | Actual Implementation Status | Key Source Files | Technical Evaluation & Findings |
| :--- | :--- | :--- | :--- |
| **1. Live Packet Sniffer (AF_PACKET)** | **Implemented & Verified** | `crates/netscope-network/src/sniffer.rs` | Uses `libc::socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)` when `CAP_NET_RAW` / root is available, with unprivileged socket observer fallback. Parses IPv4, TCP, UDP, ICMP with length and port details. Needs IPv6 header parsing and display filters. |
| **2. Inbound/Outbound Identification** | **Implemented & Verified** | `crates/netscope-core/src/sniffer.rs`, `crates/netscope-network/src/sniffer.rs` | Compares IP packet addresses against local interface IP list (`local_ips`). Correctly assigns `PacketDirection::Inbound` / `Outbound`. |
| **3. Bandwidth Waveform Graph** | **Implemented & Verified** | `src/graph.rs` | Real-time Cairo rendering 60-point sliding window with emerald green (RX) and accent blue (TX) curves. Needs hover inspection, time range options (5m, 15m, 1h), and grid units. |
| **4. Network Interface Discovery** | **Implemented & Verified** | `crates/netscope-network/src/interfaces.rs` | Parses `/sys/class/net/*` for operstate, mtu, mac, stats (rx/tx bytes, packets, dropped, errors). Handles type classification (`lo`, `eth`, `wlan`, `br`, `tun`). |
| **5. Wi-Fi / RF Monitoring** | **Implemented & Verified** | `crates/netscope-network/src/wifi.rs` | Queries `iw dev <iface> link` with `/proc/net/wireless` fallback. Correctly extracts SSID, BSSID, Signal RSSI (dBm), Link Quality %, Frequency (GHz), and Bitrate (Mbps). |
| **6. Active TCP/UDP Connections** | **Implemented & Verified** | `crates/netscope-network/src/connection.rs` | Fully parses `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6`. Maps socket state, IPv4/IPv6 endpoints, and inode numbers. |
| **7. Per-Process Socket Attribution** | **Implemented & Verified** | `crates/netscope-process/src/lib.rs` | Scans `/proc/<pid>/fd/*` symlinks matching `socket:[<inode>]`, extracting PID, executable name, commandline, UID, and username. Does not fabricate per-process bandwidth bytes (truth in telemetry). |
| **8. DNS Diagnostics & History** | **Implemented & Verified** | `crates/netscope-dns/src/lib.rs` | Inspects `/etc/resolv.conf` and `systemd-resolved` stubs. Uses `trust-dns-resolver` for asynchronous A, AAAA, MX, TXT record lookups with duration timing. |
| **9. Ping & TCP Diagnostics** | **Implemented & Verified** | `crates/netscope-network/src/diagnostics.rs` | Non-blocking TCP port connectivity via `tokio::net::TcpStream` with timeout; system `ping` output parsing for latency and packet loss. |
| **10. Kernel Routing Table** | **Implemented & Verified** | `crates/netscope-network/src/diagnostics.rs` | Reads `/proc/net/route` and decodes little-endian destination, gateway, and mask hex fields into IPv4 dotted quads. |
| **11. Offline IoC Threat Intel** | **Implemented & Verified** | `crates/netscope-security/src/threat_intel.rs` | Evaluates target IP addresses against offline hash sets of malicious C2 nodes and Tor exit nodes without sending external telemetry queries. |
| **12. Behavioral Anomaly Detection** | **Implemented & Verified** | `crates/netscope-security/src/lib.rs` | Transparent heuristic engine evaluating suspicious listening ports (e.g. 4444, 23), reserved IP range communication, new process detection, high socket count bursts, and outbound bandwidth spikes (> 200 Mbps). |
| **13. Socket Termination ("Drop")** | **Implemented & Verified** | `crates/netscope-network/src/firewall.rs` | Uses Linux `ss -K -t "dst <dst> and src <src>"` to send TCP RST without tearing down interface. Returns graceful error if unprivileged. |
| **14. Firewall IP Blocking** | **Implemented & Verified** | `crates/netscope-network/src/firewall.rs` | Direct invocation of `iptables -A OUTPUT -d <ip> -j DROP`. Requires privileges; returns safe capability warning. |
| **15. SQLite Historical Storage** | **Implemented & Verified** | `crates/netscope-storage/src/lib.rs` | SQLite in WAL mode (`PRAGMA journal_mode = WAL`). Stores bandwidth samples, DNS history, and security alerts. Includes CSV export. |
| **16. CLI Companion Tool** | **Implemented & Verified** | `crates/netscope-cli/src/main.rs` | Full Clap CLI with subcommands: `status`, `interfaces`, `traffic`, `connections`, `processes`, `dns`, `diagnostics`, `alerts`, `wifi`, `sniff`, `kill`, `export`. |

---

## 2. Technical Audit & Weaknesses Identified

### 2.1 UI/UX Architecture (`src/app.rs`)
1. **Monolithic UI File**: All GTK4 UI views were previously colocated in a single ~1,000-line `src/app.rs`. It lacked clean modular view separation.
2. **Missing Linear/Raycast Design System**: The current styling uses basic GTK CSS without unified design tokens, typography scales, elevation layers, or status badge semantics.
3. **Missing Command Palette (`Ctrl+K`)**: Power users currently have no global search or quick navigation palette.
4. **No Connection Details Inspector Side Panel**: Clicking a connection does not open an inspector drawer with reverse DNS, hex details, or deep PID metadata.
5. **UI Threading**: While background async tasks are used, some operations in `src/app.rs` still create ad-hoc threads without a unified event bus.

### 2.2 Functional Gaps (Addressed in 2.0 Roadmap)
1. **Data Usage Limits & Quotas**: No mechanism to track daily/monthly data caps (e.g., 50GB cap warning at 80%, 95%).
2. **Speed Testing Module**: Lacks an integrated network speed test benchmark (latency, jitter, upload/download speed).
3. **Network Profiles**: No concept of "Home", "Work", "Public Wi-Fi", or "VPN" profiles with tailored detection thresholds.
4. **Deep IP / Domain Investigation**: Needs an integrated whois/enrichment tool inspecting ASNs, reverse DNS, and classification.
5. **Timeline / Event Chronology**: Telemetry is categorized by tab rather than a unified unified forensic timeline of network events.
6. **Network & VPN Change Watcher**: Needs explicit detection and alerts when default gateways or VPN interfaces change.
7. **Custom Rules Editor**: Users need a visual interface to define custom alerts (e.g. "alert if process X contacts port Y").
8. **HTML/PDF Investigation Reports**: Need formatted forensic report exports beyond raw CSV.

---

## 3. Prioritized NetScope 2.0 Engineering Plan

1. **Phase 1: Code Quality & Fixes**: Clean up unused manifest fields and unused warnings; implement missing modules in `netscope-core`, `netscope-network`, and `netscope-storage`.
2. **Phase 2: Visual Design System**: Create a modern dark-first design system (`resources/styles/netscope.css`) with tokens, typography, borders, and animations inspired by Linear/Raycast/Vercel.
3. **Phase 3: Modular GUI Architecture**: Modularize `src/ui/` into dedicated controllers: `overview`, `traffic`, `connections`, `packets`, `wifi`, `dns`, `security`, `timeline`, `speedtest`, `investigate`, `profiles`, `settings`, and the global `command_palette` (`Ctrl+K`).
4. **Phase 4: Backend Feature Expansions**:
   - Data usage quota tracking and alert thresholds.
   - Built-in multi-threaded speed test engine.
   - Network profiles manager.
   - IP and domain investigation tools with offline and cached lookups.
   - Network event timeline recording interface transitions and socket lifecycles.
   - Custom user rules engine.
   - HTML investigation report generator.
5. **Phase 5: Automated Testing & Verification**: Expand integration tests for all new modules.
6. **Phase 6: Comprehensive Documentation**: Deliver updated `README.md`, `AUDIT.md`, `ARCHITECTURE.md`, `FEATURES.md`, `SECURITY.md`, `PRIVACY.md`, `INSTALLATION.md`, and `DEVELOPMENT.md`.
