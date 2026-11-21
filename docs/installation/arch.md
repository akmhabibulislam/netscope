# NetScope — Arch Linux & CachyOS Installation Guide

This guide covers installation and packaging for **Arch Linux**, **CachyOS**, **EndeavourOS**, and other Arch-based distributions.

---

## 1. Supported Distributions

- **Arch Linux** (current rolling)
- **CachyOS** (optimized rolling)
- **EndeavourOS**, **Manjaro**
- **Architecture**: `x86_64` and `x86_64-v3` / `x86_64-v4`

---

## 2. Package Dependencies

### Runtime Dependencies
- `gtk4`
- `libadwaita`
- `sqlite`
- `iproute2`
- `libcap`

### Build Dependencies
- `cargo`, `rust`
- `pkgconf`

Install with pacman:
```bash
sudo pacman -S --needed gtk4 libadwaita sqlite iproute2 libcap cargo rust
```

---

## 3. Installation via Universal Installer

From the repository root:
```bash
./install.sh
```
The script detects Arch/CachyOS, validates dependencies, builds release binaries, and stages system files under `/usr/local/` with proper capability assignment.

---

## 4. Building with PKGBUILD

NetScope includes a maintained `PKGBUILD` in `packaging/arch/PKGBUILD`:

```bash
cd packaging/arch

# Build and install package using makepkg
makepkg -si

# The resulting package netscope-0.2.0-1-x86_64.pkg.tar.zst will be installed cleanly.
```

---

## 5. Linux Capabilities Configuration

To capture raw packets without running as `root`:
```bash
sudo setcap cap_net_raw=ep /usr/local/bin/netscope-cli
```
*Note: Administrative firewall commands require explicit privilege elevation via `sudo netscope-cli firewall ...`.*

---

## 6. Uninstallation

```bash
# If installed via pacman / makepkg:
sudo pacman -R netscope

# Clean up local user config and SQLite timeline database:
rm -rf ~/.local/share/netscope ~/.config/netscope
```
