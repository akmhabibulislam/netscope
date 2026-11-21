# NetScope — Fedora Linux Installation & Operational Guide

This document provides verified, native installation instructions for **NetScope** on Fedora Linux.

---

## 1. Supported Fedora Versions & Architecture

NetScope is officially verified on:
- **Fedora Workstation 41** (x86_64)
- **Fedora Workstation 40** (x86_64)
- **Fedora Workstation 39** (x86_64)
- **Architecture**: `x86_64` (AMD64 / Intel 64-bit)

---

## 2. Package Dependencies

### Runtime Dependencies
These libraries are standard on Fedora Workstation:
- `gtk4` (>= 4.10)
- `libadwaita` (>= 1.4)
- `sqlite-libs` (>= 3.35)
- `iproute`
- `libcap`

### Build Dependencies (for building RPM from source)
- `cargo`, `rust`, `gcc`
- `gtk4-devel`, `libadwaita-devel`, `sqlite-devel`, `libcap-devel`
- `rpm-build`, `desktop-file-utils`

To install all build dependencies at once:
```bash
sudo dnf install -y cargo rust gcc gtk4-devel libadwaita-devel sqlite-devel libcap-devel rpm-build desktop-file-utils
```

---

## 3. Installation from Release RPM

When downloading a published `.rpm` package from NetScope Releases:

```bash
# 1. Download release RPM
curl -LO https://github.com/akmhabibulislam/netscope/releases/latest/download/netscope-0.2.0-1.fc40.x86_64.rpm

# 2. Install using DNF (automatically handles dependencies)
sudo dnf install -y ./netscope-0.2.0-1.fc40.x86_64.rpm

# 3. Verify installation
netscope --version
netscope-cli status
```

---

## 4. Automated Native Fedora Installer

The repository includes a dedicated Fedora installation script that detects dependencies, builds or locates the RPM, and configures permissions:

```bash
git clone https://github.com/akmhabibulislam/netscope.git
cd netscope

# Run the native Fedora installer
./installers/fedora/install.sh
```

---

## 5. Building the RPM Package Locally

To build a clean native RPM package from the local source:

```bash
# Build the RPM package
./packaging/fedora/build-rpm.sh

# The resulting package will be in:
# target/rpmbuild/RPMS/x86_64/netscope-0.2.0-1.fc*.x86_64.rpm

# Install your built RPM
sudo dnf install -y target/rpmbuild/RPMS/x86_64/netscope-*.rpm
```

---

## 6. Desktop Integration & Launching

### Launching the Graphical Interface
- **Application Menu**: Search for **NetScope** in GNOME Shell / Application Launcher.
- **Terminal (as standard user)**:
  ```bash
  netscope
  ```
> **SECURITY MANDATE**: Never run `sudo netscope` or run the GUI desktop application as root. NetScope is built with least-privilege architecture.

### Launching the CLI Companion
```bash
# General status
netscope-cli status

# Live continuous traffic monitoring
netscope-cli traffic --interface wlan0

# Flow session inspection
netscope-cli flows --duration-secs 10

# Threat intelligence database inspection
netscope-cli threats
```

---

## 7. Permissions & Linux Capabilities

NetScope requires privileges only for specific low-level kernel operations:

1. **Hardware Raw Packet Sniffer (`AF_PACKET`)**:
   Requires `CAP_NET_RAW` Linux capability. The RPM package automatically sets this capability on `/usr/bin/netscope-cli` during installation:
   ```bash
   sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/netscope-cli
   ```
   This allows ordinary users to capture packets without needing `sudo`.

2. **Firewall Kill-Switch (`iptables` / `nftables`)**:
   Emergency traffic isolation modifies kernel netfilter chains. These commands require elevated privileges when invoked:
   ```bash
   sudo netscope-cli firewall --activate-killswitch
   sudo netscope-cli firewall --deactivate-killswitch
   ```

---

## 8. SELinux Compatibility

Fedora runs with **SELinux Enforcing** by default. NetScope fully supports SELinux in Enforcing mode:
- All binaries reside in standard `/usr/bin/` paths with `bin_t` labeling.
- Desktop entries reside in `/usr/share/applications/` with `usr_t` labeling.
- User data resides in standard XDG paths (`~/.local/share/netscope/`, `~/.config/netscope/`) with `data_home_t` labeling.
- **Do not disable SELinux**. NetScope operates cleanly with SELinux Enforcing.

Verify SELinux status:
```bash
sestatus
```

---

## 9. Updating NetScope

To upgrade an existing installation when a new RPM release is available:
```bash
sudo dnf upgrade -y ./netscope-*.rpm
```

---

## 10. Uninstallation

To safely remove NetScope from Fedora:

```bash
# Option A: Using the native uninstaller script
./installers/fedora/uninstall.sh

# Option B: Direct DNF package removal
sudo dnf remove -y netscope

# To purge user databases and timeline logs as well:
./installers/fedora/uninstall.sh --purge
```
