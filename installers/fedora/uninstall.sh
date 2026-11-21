#!/usr/bin/env bash
# ==============================================================================
# NetScope — Fedora Linux Native Uninstallation Script
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

PURGE=false
if [[ "${1:-}" == "--purge" || "${1:-}" == "-p" ]]; then
    PURGE=true
fi

echo -e "${BOLD}======================================================"
echo -e "   NetScope — Fedora Linux Native Uninstaller"
echo -e "======================================================${RESET}"

# Privilege check
SUDO_CMD=""
if [[ $EUID -ne 0 ]]; then
    if command -v sudo &>/dev/null; then
        SUDO_CMD="sudo"
    else
        log_err "Root privileges or 'sudo' required to remove system packages via DNF."
        exit 1
    fi
fi

if rpm -q netscope &>/dev/null; then
    log_info "Removing NetScope RPM package via DNF..."
    ${SUDO_CMD} dnf remove -y netscope
    log_ok "NetScope system package successfully removed."
else
    log_warn "NetScope RPM package is not currently installed."
fi

# Clean up desktop database & icon cache
if command -v update-desktop-database &>/dev/null; then
    ${SUDO_CMD} update-desktop-database &>/dev/null || :
fi
if command -v gtk4-update-icon-cache &>/dev/null; then
    ${SUDO_CMD} gtk4-update-icon-cache /usr/share/icons/hicolor &>/dev/null || :
fi

# User data handling
USER_DATA_DIR="${HOME}/.local/share/netscope"
USER_CONFIG_DIR="${HOME}/.config/netscope"

if [[ "${PURGE}" == true ]]; then
    log_warn "Purge option requested. Deleting user data and configuration..."
    rm -rf "${USER_DATA_DIR}" "${USER_CONFIG_DIR}"
    log_ok "User database and settings purged."
else
    echo
    log_info "User configuration and forensic timeline databases preserved:"
    echo "  - Config: ${USER_CONFIG_DIR}"
    echo "  - Database: ${USER_DATA_DIR}"
    echo "To completely erase user databases and forensic timeline history, run:"
    echo "  ${0} --purge"
fi

echo
log_ok "NetScope uninstallation complete."
