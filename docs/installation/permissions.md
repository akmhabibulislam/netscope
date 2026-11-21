# NetScope — Permissions, Privileges & Security Architecture

NetScope follows a strict **least-privilege design**. Network applications that interact with hardware interfaces and firewall rules must never compromise the host operating system.

---

## 1. Why NetScope GUI Never Runs as Root

Running complex graphical user interfaces (GTK4, WebKit, Wayland/X11 clients) as `root` violates Linux security standards:
- Desktop rendering stacks are not audited for root execution.
- Any memory safety or parsing flaw in UI components would run with full kernel-level permissions.
- Root GUI processes pollute unprivileged user desktop configuration directories with root-owned files.

**Policy**: NetScope GUI (`netscope`) must **always** run as your ordinary desktop user.

---

## 2. Granular Privileges by Feature

| NetScope Feature | Required Privilege | Mechanism Used |
| :--- | :--- | :--- |
| **Interface Stats, WiFi & Bandwidth** | Unprivileged | Linux `/proc/net/dev`, `/sys/class/net/` |
| **Active Sockets & Connections** | Unprivileged | Linux `/proc/net/tcp`, `/proc/net/udp` netlink |
| **DNS Intelligence & Querying** | Unprivileged | Standard UDP socket to configured resolvers |
| **Threat Intelligence Matching** | Unprivileged | In-memory evaluation against offline DB |
| **AF_PACKET Raw Sniffing** | `CAP_NET_RAW` | Linux File Capabilities (`setcap`) |
| **TCP Socket Termination (`ss -K`)** | `CAP_NET_ADMIN` | Linux File Capabilities or targeted `sudo` |
| **Firewall Killswitch Activation** | `CAP_NET_ADMIN` | Dedicated `netscope-cli firewall` via `sudo` |

---

## 3. Configuring Linux Capabilities (Recommended)

To allow ordinary desktop users to capture live raw packets with the sniffer without granting root access, Linux File Capabilities are used:

```bash
# Grant packet sniffing capability (CAP_NET_RAW) without granting firewall admin
sudo setcap cap_net_raw=ep $(which netscope-cli)

# Verify capability assignment:
getcap $(which netscope-cli)
# Output: /usr/bin/netscope-cli cap_net_raw=ep
```

> **Least-Privilege Notice**: NetScope strictly separates packet analysis from network administration. Packet capture requires only `CAP_NET_RAW`. Administrative operations (such as firewall manipulation and socket teardown) are not granted via ambient binary capabilities; they require explicit invocation through `sudo netscope-cli firewall ...`.

---

## 4. Firewall Administration

NetScope uses application-owned custom netfilter chains (`NETSCOPE_IN`, `NETSCOPE_OUT`, `NETSCOPE_BLOCK`) and transactional rollback to ensure unrelated user rules are never modified or flushed.

Firewall modifications require `CAP_NET_ADMIN`. Use the dedicated CLI companion:

```bash
# Block a malicious remote IP
sudo netscope-cli firewall --block 203.0.113.50

# Unblock IP
sudo netscope-cli firewall --unblock 203.0.113.50

# Transactional killswitch isolation
sudo netscope-cli firewall --activate-killswitch
sudo netscope-cli firewall --deactivate-killswitch
```

---

## 5. SELinux Security Policy

NetScope is verified with **SELinux in Enforcing mode**:
- Does not require disabling SELinux (`setenforce 0`).
- Does not create custom kernel modules or unauthorized memory mappings.
- Confines socket operations strictly to standard Linux AF_PACKET and AF_INET protocols.
