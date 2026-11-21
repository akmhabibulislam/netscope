# NetScope — Installation & Runtime Troubleshooting

This guide addresses common setup and operational issues.

---

## 1. Raw Socket Permission Denied (`CAP_NET_RAW required`)

### Symptom
When starting the live sniffer in the GUI or CLI:
```text
AF_PACKET raw socket permission denied: CAP_NET_RAW capability required.
```

### Cause
Linux requires `CAP_NET_RAW` to open raw packet capture sockets.

### Resolution
Apply file capabilities to the binary:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which netscope-cli)
```

---

## 2. Missing GTK4 or Libadwaita Development Headers on Fedora

### Symptom
During `cargo build` or RPM compilation:
```text
Package gtk4 was not found in the pkg-config search path.
```

### Resolution
Install the required development packages:
```bash
sudo dnf install -y gtk4-devel libadwaita-devel sqlite-devel libcap-devel
```

---

## 3. Firewall Rollback or Missing Backend

### Symptom
```text
No supported firewall backend found. Ensure iptables or nftables is installed.
```

### Resolution
Install your distribution's netfilter package:
- **Fedora**: `sudo dnf install -y iptables nftables`
- **Arch / CachyOS**: `sudo pacman -S iptables-nft`

NetScope automatically detects whether `nftables` or `iptables` is available and selects the corresponding commands safely.

---

## 4. Desktop Icon Not Displaying

### Symptom
The desktop entry appears, but the icon is missing in GNOME / KDE / Wayland.

### Resolution
Update the system icon and desktop databases:
```bash
sudo update-desktop-database /usr/share/applications
sudo gtk4-update-icon-cache -f /usr/share/icons/hicolor
```

---

## 5. Wayland / Display Server Warnings

### Symptom
```text
Gdk-WARNING **: Wayland display connection closed
```

### Resolution
Ensure your graphics driver and Wayland compositor (Mutter / KWin / Sway / Hyprland) are functioning properly. To force X11 backend if Wayland is misbehaving:
```bash
GDK_BACKEND=x11 netscope
```
