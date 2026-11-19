#!/usr/bin/env bash
# NetScope Linux Desktop Installer
# Installs NetScope binaries, desktop integration, icons, and capabilities.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_GUI="$SCRIPT_DIR/target/release/netscope"
BIN_CLI="$SCRIPT_DIR/target/release/netscope-cli"
DESKTOP_SRC="$SCRIPT_DIR/resources/netscope.desktop"
ICON_SRC="$SCRIPT_DIR/resources/icons/netscope.svg"

# Determine installation scope
PREFIX="${PREFIX:-}"
if [ -z "$PREFIX" ]; then
    if [ "$EUID" -eq 0 ]; then
        PREFIX="/usr/local"
    else
        PREFIX="$HOME/.local"
    fi
fi

BIN_DIR="$PREFIX/bin"
APP_DIR="$PREFIX/share/applications"
ICON_DIR="$PREFIX/share/icons/hicolor/scalable/apps"
DOC_DIR="$PREFIX/share/doc/netscope"

echo "=== Installing NetScope 2.0 ==="
echo "Target Prefix: $PREFIX"

if [ ! -f "$BIN_GUI" ]; then
    echo "Error: Release binary '$BIN_GUI' not found."
    echo "Please build first using: cargo build --release"
    exit 1
fi

mkdir -p "$BIN_DIR" "$APP_DIR" "$ICON_DIR" "$DOC_DIR"

echo "Installing binaries..."
install -Dm755 "$BIN_GUI" "$BIN_DIR/netscope-gui"
# Create a symlink or binary for netscope -> netscope-gui
ln -sf "$BIN_DIR/netscope-gui" "$BIN_DIR/netscope"

if [ -f "$BIN_CLI" ]; then
    install -Dm755 "$BIN_CLI" "$BIN_DIR/netscope-cli"
    echo "Installed: $BIN_DIR/netscope-cli"
fi

echo "Installed: $BIN_DIR/netscope-gui"
echo "Installed: $BIN_DIR/netscope"

echo "Installing desktop shortcut & icon..."
install -Dm644 "$ICON_SRC" "$ICON_DIR/netscope.svg"
install -Dm644 "$DESKTOP_SRC" "$APP_DIR/netscope.desktop"

# Optional: setcap for unprivileged raw packet capture if running as root or with sudo
if command -v setcap >/dev/null 2>&1; then
    if [ "$EUID" -eq 0 ]; then
        echo "Granting cap_net_raw,cap_net_admin to $BIN_DIR/netscope-gui for hardware packet sniffer..."
        setcap cap_net_raw,cap_net_admin+eip "$BIN_DIR/netscope-gui" || true
    else
        echo "Tip: Run 'sudo setcap cap_net_raw,cap_net_admin+eip $BIN_DIR/netscope-gui' if you want unprivileged raw packet sniffing."
    fi
fi

# Update desktop database if available
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APP_DIR" 2>/dev/null || true
fi

# Update icon cache if available
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$PREFIX/share/icons/hicolor" 2>/dev/null || true
fi

echo ""
echo "=== NetScope Successfully Installed! ==="
echo "Launch from your desktop application launcher (App Menu / Rofi / Wofi / GNOME / KDE)"
echo "Or run in terminal: netscope"
