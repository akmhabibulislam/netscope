# Security Policy

The NetScope team takes security, user privacy, and defensive isolation seriously. Because NetScope monitors network sockets, packet streams, and interface states, ensuring that NetScope itself remains resilient against exploitation is a paramount priority.

---

## 🛡️ Supported Versions

Only the latest release and the current `main` branch receive active security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x:                |
| < 0.1.0 | :x:                |

---

## 🔒 Reporting a Vulnerability

If you discover a security vulnerability, privilege escalation path, denial-of-service vector, or memory safety defect in NetScope:

1. **Do not create a public issue** on GitHub.
2. Email your findings directly to the maintainers at **`dev@netscope.internal`** or open a **Private Vulnerability Report** via GitHub Security Advisories.
3. Include:
   - A clear description of the vulnerability.
   - Proof-of-concept steps or exploit code.
   - The affected component (e.g. `netscope-network`, `netscope-process`).
   - Impact assessment on host systems.

### Response Timeline
- **Initial Acknowledgement**: Within 48 hours.
- **Triage & Status Update**: Within 5 business days.
- **Remediation & Patch**: Coordinated disclosure with patch release within 14–30 days depending on complexity.

---

## ⚙️ Security Architecture & Threat Model

### 1. Privilege Separation & Capabilities
NetScope is designed to run entirely without `root` (`sudo`) for the vast majority of functions (socket enumeration, bandwidth monitoring, process attribution, DNS querying, and anomaly detection). For raw packet sniffing (`AF_PACKET`), NetScope leverages Linux file capabilities:
```bash
sudo setcap cap_net_raw,cap_net_admin+eip <binary>
```
This isolates raw socket operations without granting full root execution privileges.

### 2. Privacy & Telemetry
NetScope communicates only with remote hosts when explicitly initiated by user interaction (e.g., DNS diagnostic lookups, ping/tcp reachability checks, or speedtests). 
- **Zero background telemetry**
- **Zero external tracking**
- **Offline IoC matching** against local Bloom filters / HashSets
