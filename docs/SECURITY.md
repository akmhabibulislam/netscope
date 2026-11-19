# NetScope 2.0 Security Architecture & Threat Model

## 1. Local-First & Privacy Guarantees
NetScope operates strictly locally by default:
- No background telemetry or heartbeat pings are sent to any centralized server.
- Destination IP addresses and queried domains are never sent to third parties for analysis.
- Threat intelligence evaluation (C2 nodes, Tor exit nodes) runs **completely offline** against locally maintained signatures.
- External enrichment (e.g. IP geolocation or speed testing) is strictly optional, clearly labeled, and requires user consent.

## 2. Unprivileged Kernel Interface Usage
NetScope avoids requiring `sudo` or setuid root for standard monitoring:
- **Bandwidth Counters**: Read from unprivileged sysfs files (`/sys/class/net/<iface>/statistics/`).
- **Active Connections**: Read from unprivileged procfs files (`/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6`).
- **Process Attribution**: Scans file descriptor symlinks in `/proc/<pid>/fd/` belonging to the current user and unprivileged processes.

## 3. Privileged Operations Isolation
Certain advanced actions require elevated capabilities:
- **Socket Termination (`ss -K`)**: Requires `CAP_NET_ADMIN`. If unprivileged, NetScope intercepts the error and presents a clear diagnostic warning without crashing or escalating silently.
- **Firewall IP Blocking (`iptables / nftables`)**: Modifying kernel netfilter chains requires root or `CAP_NET_ADMIN`.
- **Raw Packet Capture**: `AF_PACKET` raw sockets require `CAP_NET_RAW`. When missing, NetScope falls back to socket-level sampling.
