# NetScope Development & Architecture Guide

## Workspace Crates
- `netscope-core`: Domain models, serialization, timeline events, quota definitions, and packet summaries.
- `netscope-network`: Interface statistics discovery, socket state parsing, Wi-Fi analytics, benchmark speed test engine, IP forensics investigator, and AF_PACKET sniffer.
- `netscope-process`: Inode resolution to PIDs and binaries via Linux procfs.
- `netscope-dns`: Asynchronous DNS client and resolver configuration inspector.
- `netscope-security`: Heuristic anomaly detection rules and offline IoC threat match engine.
- `netscope-storage`: SQLite WAL storage with schema migrations and report export.
- `netscope-platform`: Freedesktop desktop notifications.
- `netscope-cli`: Terminal companion application powered by Clap.

## Building and Running Tests
```bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
```
