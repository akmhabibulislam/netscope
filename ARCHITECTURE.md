# NetScope Architecture & Technical Design

This document details the internal architecture, event loops, thread model, data flow, and security boundaries of **NetScope**.

---

## 🏛️ System Overview

NetScope follows a multi-crate, decoupled architecture built around the Linux networking stack:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        User Interface Layer                            │
│   ┌───────────────────────────┐      ┌─────────────────────────────┐   │
│   │  GTK4 / Libadwaita GUI    │      │  NetScope CLI Companion     │   │
│   │  (netscope / src/)        │      │  (netscope-cli)             │   │
│   └─────────────┬─────────────┘      └──────────────┬──────────────┘   │
└─────────────────┼───────────────────────────────────┼──────────────────┘
                  │                                   │
┌─────────────────▼───────────────────────────────────▼──────────────────┐
│                   Application State & Event Hub                        │
│   ┌─────────────────────────────────────────────────────────────┐      │
│   │  Shared Thread-Safe AppState (Arc<RwLock<...>>)             │      │
│   └─────────────────────────────┬───────────────────────────────┘      │
└─────────────────────────────────┼──────────────────────────────────────┘
                                  │
┌─────────────────────────────────▼──────────────────────────────────────┐
│                        Engine & Subsystems                             │
│   ┌───────────────────────┐ ┌──────────────────────┐ ┌───────────────┐ │
│   │ netscope-network      │ │ netscope-process     │ │ netscope-dns  │ │
│   │ - AF_PACKET Sniffer   │ │ - /proc/<pid>/fd/    │ │ - System      │ │
│   │ - Cairo Waveform Math │ │ - Inode Resolution   │ │   Resolvers   │ │
│   │ - Wi-Fi RF Telemetry  │ │ - Process Tree Cache │ │ - Async Probe │ │
│   │ - Speedtest Benchmark │ └──────────────────────┘ └───────────────┘ │
│   └───────────────────────┘                                            │
│   ┌───────────────────────┐ ┌──────────────────────┐ ┌───────────────┐ │
│   │ netscope-security     │ │ netscope-storage     │ │ netscope-core │ │
│   │ - Anomaly Heuristics  │ │ - SQLite WAL Engine  │ │ - Domain      │ │
│   │ - Offline Threat IoC  │ │ - Telemetry History  │ │   Primitives  │ │
│   │ - Active Socket Drop  │ │ - Export (CSV/JSON)  │ │ - Event Types │ │
│   └───────────────────────┘ └──────────────────────┘ └───────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

---

## ⚙️ Core Subsystems

### 1. Packet Sniffer Engine (`netscope-network::sniffer`)
- **Dual-Mode Capture**:
  - **Raw Mode (`AF_PACKET`)**: Directly opens a low-level Linux raw packet socket bound to `ETH_P_ALL` when permissions (`CAP_NET_RAW`) allow. Decodes Ethernet frames, IPv4/IPv6 headers, TCP/UDP/ICMP payloads, and DNS queries with byte accuracy.
  - **Unprivileged Polling Fallback**: When raw socket capabilities are absent, polls active socket deltas at 100ms intervals, allowing regular users to still inspect connection changes without needing root.
- **Directional Classification**: Compares packet source and destination addresses against the host's assigned IP addresses on active interfaces to categorize packets as `INBOUND` or `OUTBOUND`.

### 2. Animated Waveform Engine (`src/graph.rs`)
- Uses **Cairo 2D rendering** driven by a GLib 60 FPS tick callback.
- Maintains rolling circular ring buffers (60 data points) of instantaneous download ($RX$) and upload ($TX$) transfer rates.
- Computes cubic Bézier spline interpolation across sample points for fluid aesthetic waveform animations.

### 3. Socket Inode Resolution (`netscope-process`)
- Scans `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, and `/proc/net/udp6` to extract socket states and their virtual inode numbers.
- Traverses `/proc/<pid>/fd/` links matching target socket inodes to identify the owning PID, process name, and executable path.
- Employs an LRU attribution cache to minimize filesystem traversal overhead.

### 4. Offline Threat Intelligence & Heuristics (`netscope-security`)
- **Privacy By Default**: Rather than querying remote threat feeds with the user's active IP connections, NetScope embeds high-reputation curated IoC sets locally.
- **Heuristic Analyzers**:
  - Detects suspicious reverse shell ports (e.g. 4444, 31337, 1337).
  - Outbound bandwidth bursts exceeding configured thresholds.
  - Sockets communicating with RFC 5737 / RFC 3849 test addresses.

### 5. Persistent Historical Telemetry (`netscope-storage`)
- Embedded SQLite engine running with **Write-Ahead Logging (WAL)** enabled (`PRAGMA journal_mode = WAL`).
- Automatically aggregates throughput metrics and connection logs into hourly and daily rollups.
