#!/usr/bin/env bash
# ==============================================================================
# NetScope — Distribution-Aware Universal Linux Installer
# Detects operating system and routes to the appropriate native installation flow.
# Supported Distributions: Fedora, Arch Linux, CachyOS
# ==============================================================================
set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
RESET="\033[0m"

log_info() { echo -e "${BLUE}[*]${RESET} ${1}"; }
log_ok() { echo -e "${GREEN}[+]${RESET} ${1}"; }
log_warn() { echo -e "${YELLOW}[!]${RESET} ${1}"; }
log_err() { echo -e "${RED}[ERROR]${RESET} ${1}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BOLD}======================================================"
echo -e "   NetScope — Linux Distribution Installer"
echo -e "======================================================${RESET}"

if [ ! -f /etc/os-release ]; then
    log_err "Cannot detect operating system: /etc/os-release is missing."
    echo "Please refer to docs/installation/ for manual installation instructions."
    exit 1
fi

# shellcheck source=/dev/null
source /etc/os-release
OS_ID="${ID:-}"
OS_LIKE="${ID_LIKE:-}"

log_info "Detected operating system: ${PRETTY_NAME:-unknown} (ID: ${OS_ID})"

install_arch() {
    log_info "Using Arch-compatible packaging and installation flow..."

    # Check required build/runtime dependencies
    MISSING_DEPS=()
    for dep in gtk4 libadwaita sqlite iproute2 libcap cargo rust; do
        if ! pacman -Q "${dep}" &>/dev/null; then
            MISSING_DEPS+=("${dep}")
        fi
    done

    if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
        log_warn "Missing required dependencies: ${MISSING_DEPS[*]}"
        read -r -p "Install missing dependencies with 'sudo pacman -S'? [Y/n]: " CONFIRM_PACMAN
        CONFIRM_PACMAN=${CONFIRM_PACMAN:-Y}
        if [[ "${CONFIRM_PACMAN}" =~ ^[Yy]$ ]]; then
            sudo pacman -S --needed "${MISSING_DEPS[@]}"
        else
            log_err "Cannot proceed without required dependencies."
            exit 1
        fi
    fi

    log_info "Building release binaries from repository source..."
    cd "${SCRIPT_DIR}"
    cargo build --release --workspace

    PREFIX="${PREFIX:-/usr/local}"
    BIN_DIR="${PREFIX}/bin"
    APP_DIR="${PREFIX}/share/applications"
    ICON_DIR="${PREFIX}/share/icons/hicolor/scalable/apps"

    SUDO_CMD=""
    if [[ $EUID -ne 0 ]]; then
        SUDO_CMD="sudo"
    fi

    log_info "Installing binaries and desktop integration to ${PREFIX}..."
    ${SUDO_CMD} install -Dm755 "${SCRIPT_DIR}/target/release/netscope" "${BIN_DIR}/netscope-gui"
    ${SUDO_CMD} ln -sf "netscope-gui" "${BIN_DIR}/netscope"
    ${SUDO_CMD} install -Dm755 "${SCRIPT_DIR}/target/release/netscope-cli" "${BIN_DIR}/netscope-cli"
    ${SUDO_CMD} install -Dm644 "${SCRIPT_DIR}/resources/netscope.desktop" "${APP_DIR}/netscope.desktop"
    ${SUDO_CMD} install -Dm644 "${SCRIPT_DIR}/resources/icons/netscope.svg" "${ICON_DIR}/netscope.svg"

    # Configure network capabilities on CLI companion (CAP_NET_RAW only for packet capture)
    if command -v setcap &>/dev/null; then
        log_info "Setting network capability (CAP_NET_RAW) on netscope-cli..."
        ${SUDO_CMD} setcap cap_net_raw=ep "${BIN_DIR}/netscope-cli" || true
    fi

    if command -v update-desktop-database &>/dev/null; then
        ${SUDO_CMD} update-desktop-database "${APP_DIR}" 2>/dev/null || true
    fi
    if command -v gtk4-update-icon-cache &>/dev/null; then
        ${SUDO_CMD} gtk4-update-icon-cache "${PREFIX}/share/icons/hicolor" 2>/dev/null || true
    fi

    echo
    log_ok "NetScope successfully installed on ${PRETTY_NAME}!"
    echo "Launch GUI: netscope"
    echo "Launch CLI: netscope-cli status"
    echo "Note: Packet sniffing runs unprivileged via CAP_NET_RAW. Firewall controls require 'sudo netscope-cli firewall ...'."
}

case "${OS_ID}" in
    fedora)
        log_info "Routing to Fedora native RPM installation process..."
        exec "${SCRIPT_DIR}/installers/fedora/install.sh" "$@"
        ;;
    arch|cachyos|endeavouros|manjaro|artix|garuda|archarm)
        log_info "Detected Arch-based Linux (${OS_ID})."
        install_arch
        ;;
    *)
        if [[ "${OS_LIKE}" =~ (fedora|rhel) ]]; then
            log_info "Distribution is Fedora/RHEL-like. Routing to Fedora RPM installer..."
            exec "${SCRIPT_DIR}/installers/fedora/install.sh" "$@"
        elif [[ "${OS_LIKE}" =~ arch ]]; then
            log_info "Distribution is Arch-like (${OS_LIKE})."
            install_arch
        else
            echo
            log_warn "Distribution '${OS_ID}' (${PRETTY_NAME:-unknown}) does not have an automated native installer."
            echo
            echo "You can manually install NetScope from source on any modern Linux system:"
            echo "  1. Install GTK4, Libadwaita, SQLite, and Rust toolchain."
            echo "  2. Run: cargo build --release"
            echo "  3. Copy 'target/release/netscope' and 'target/release/netscope-cli' to /usr/local/bin/"
            echo "  4. See docs/installation/troubleshooting.md for detailed instructions."
            exit 1
        fi
        ;;
esac
