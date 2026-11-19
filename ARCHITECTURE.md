# NetScope Architecture

## Overview
NetScope decouples data acquisition, security heuristics, storage, and presentation.

```
┌────────────────────────────────────────────────────────┐
│                   NetScope Frontend                    │
│      GTK4 / Libadwaita Desktop GUI  &  CLI Companion    │
└───────────────────────────▲────────────────────────────┘
                            │
┌───────────────────────────┴────────────────────────────┐
│                  Application Runtime                   │
│   Tokio Asynchronous Core & GLib Event Integration     │
└─────▲─────────────────────▲──────────────────────▲─────┘
      │                     │                      │
┌─────┴──────────────┐ ┌────┴────────────────┐ ┌───┴───────────────┐
│ netscope-network   │ │ netscope-security   │ │ netscope-storage  │
│  - /sys/class/net  │ │  - High-risk ports  │ │  - SQLite WAL     │
│  - /proc/net/tcp*  │ │  - Traffic spikes   │ │  - Historical DB  │
│  - /proc/net/udp*  │ │  - Process tracking │ │  - CSV Export     │
│  - Diagnostics     │ └─────────────────────┘ └───────────────────┘
└─────▲──────────────┘
      │
┌─────┴──────────────┐
│ netscope-process   │
│  - /proc/<pid>/fd  │
│  - Inode to PID    │
└────────────────────┘
```

## Linux Kernel Interface Utilization
1. **Bandwidth & Counters**: Evaluated directly from `/sys/class/net/<iface>/statistics/rx_bytes` and `tx_bytes`.
2. **Socket Discovery**: Extracted from unprivileged `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, and `/proc/net/udp6`.
3. **Socket to Process Resolution**: Discovered by mapping socket inodes to `/proc/<pid>/fd/*` symlinks matching `socket:[<inode>]`.
4. **Routing**: Derived from `/proc/net/route`.
5. **DNS Configuration**: Read from `/etc/resolv.conf` and `systemd-resolved` stubs.
