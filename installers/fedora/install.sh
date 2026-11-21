#!/usr/bin/env bash
# ==============================================================================
# NetScope — Fedora Linux Native Installation Script
# Supported Versions: Fedora Workstation 39, 40, 41 (x86_64)
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

echo -e "${BOLD}======================================================"
echo -e "   NetScope — Fedora Linux Native Installer"
echo -e "======================================================${RESET}"

# 1. Distribution Detection
if [ ! -f /etc/os-release ]; then
    log_err "Cannot verify operating system: /etc/os-release is missing."
    exit 1
fi

# shellcheck source=/dev/null
source /etc/os-release
if [[ "${ID:-}" != "fedora" ]]; then
    log_err "This installation script is specifically designed for Fedora Linux."
    echo "Detected OS: ${PRETTY_NAME:-unknown} (ID: ${ID:-unknown})"
    echo "For Arch/CachyOS, use the root 'install.sh' or 'packaging/arch/PKGBUILD'."
    exit 1
fi
log_ok "Detected supported distribution: ${PRETTY_NAME}"

# 2. Architecture Check
ARCH="$(uname -m)"
if [[ "${ARCH}" != "x86_64" ]]; then
    log_err "Unsupported CPU architecture: ${ARCH}. NetScope currently targets x86_64."
    exit 1
fi
log_ok "Architecture verified: ${ARCH}"

# 3. Privilege Check
SUDO_CMD=""
if [[ $EUID -ne 0 ]]; then
    if command -v sudo &>/dev/null; then
        SUDO_CMD="sudo"
        log_info "Unprivileged session detected. 'sudo' will be used for package management."
    else
        log_err "Root privileges or 'sudo' required to install system packages via DNF."
        exit 1
    fi
else
    log_warn "Running as root user. NetScope desktop GUI should always be launched as an unprivileged user."
fi

# 4. Dependency Inspection & Installation
REQUIRED_PKGS=(gtk4 libadwaita sqlite-libs iproute libcap)
MISSING_PKGS=()

for pkg in "${REQUIRED_PKGS[@]}"; do
    if ! rpm -q "${pkg}" &>/dev/null; then
        MISSING_PKGS+=("${pkg}")
    fi
done

if [[ ${#MISSING_PKGS[@]} -gt 0 ]]; then
    echo
    log_info "The following required runtime packages are not currently installed:"
    for mp in "${MISSING_PKGS[@]}"; do
        echo "  - ${mp}"
    done
    echo
    read -r -p "Install missing dependencies via DNF now? [Y/n]: " CONFIRM_DEP
    CONFIRM_DEP=${CONFIRM_DEP:-Y}
    if [[ "${CONFIRM_DEP}" =~ ^[Yy]$ ]]; then
        log_info "Installing missing dependencies via DNF..."
        ${SUDO_CMD} dnf install -y "${MISSING_PKGS[@]}"
    else
        log_err "Cannot proceed without required dependencies."
        exit 1
    fi
else
    log_ok "All required runtime dependencies are satisfied."
fi

# 5. Locate or Build NetScope RPM Package
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RPM_FILE=""

# Check if pre-built RPM is provided in arguments or dist directory
if [[ $# -gt 0 && -f "$1" ]]; then
    RPM_FILE="$1"
elif compgen -G "${REPO_ROOT}/target/rpmbuild/RPMS/x86_64/netscope-*.rpm" > /dev/null; then
    RPM_FILE="$(ls -t "${REPO_ROOT}/target/rpmbuild/RPMS/x86_64"/netscope-*.rpm | head -n1)"
elif compgen -G "${REPO_ROOT}/dist/netscope-*.rpm" > /dev/null; then
    RPM_FILE="$(ls -t "${REPO_ROOT}/dist"/netscope-*.rpm | head -n1)"
fi

if [[ -z "${RPM_FILE}" || ! -f "${RPM_FILE}" ]]; then
    log_info "No pre-compiled RPM package found. Initiating local RPM build..."
    if ! command -v rpmbuild &>/dev/null; then
        echo
        log_info "Package 'rpm-build' is needed to construct native RPM."
        read -r -p "Install development dependencies (rpm-build, cargo, etc.)? [Y/n]: " CONFIRM_BUILD_DEP
        CONFIRM_BUILD_DEP=${CONFIRM_BUILD_DEP:-Y}
        if [[ "${CONFIRM_BUILD_DEP}" =~ ^[Yy]$ ]]; then
            ${SUDO_CMD} dnf install -y rpm-build cargo rust gcc gtk4-devel libadwaita-devel sqlite-devel libcap-devel desktop-file-utils
        else
            log_err "Aborting: cannot build RPM without packaging tools."
            exit 1
        fi
    fi

    "${REPO_ROOT}/packaging/fedora/build-rpm.sh"
    RPM_FILE="$(ls -t "${REPO_ROOT}/target/rpmbuild/RPMS/x86_64"/netscope-*.rpm | head -n1)"
fi

# 6. Verify Package
if [[ ! -f "${RPM_FILE}" ]]; then
    log_err "Failed to obtain valid NetScope RPM package."
    exit 1
fi
log_ok "Found NetScope RPM package: ${RPM_FILE}"

# 7. Package Installation via DNF
log_info "Installing NetScope package via DNF..."
${SUDO_CMD} dnf install -y "${RPM_FILE}"

# 8. Post-Installation Verification
echo
log_info "Verifying installed system binaries and desktop assets..."
if command -v netscope &>/dev/null && command -v netscope-cli &>/dev/null; then
    log_ok "Executable binaries verified:"
    echo "  - GUI: $(which netscope)"
    echo "  - CLI: $(which netscope-cli)"
else
    log_err "Binary verification failed. Executables not found in PATH."
    exit 1
fi

if [[ -f "/usr/share/applications/netscope.desktop" ]]; then
    log_ok "Desktop entry verified: /usr/share/applications/netscope.desktop"
else
    log_warn "Desktop entry not detected in /usr/share/applications/."
fi

# 9. Capability Verification
if command -v getcap &>/dev/null; then
    CLI_PATH="$(which netscope-cli)"
    CAPS="$(getcap "${CLI_PATH}" || true)"
    if [[ -n "${CAPS}" ]]; then
        log_ok "Network capabilities configured: ${CAPS}"
    else
        log_warn "Linux capabilities not set on ${CLI_PATH}. Run without root:"
        echo "  sudo setcap cap_net_raw,cap_net_admin=eip ${CLI_PATH}"
    fi
fi

echo
echo -e "${GREEN}${BOLD}NetScope installed successfully on Fedora!${RESET}"
echo
echo "Quick Start:"
echo "  1. Launch Desktop GUI: netscope (or find 'NetScope' in the application menu)"
echo "  2. Run CLI Status:     netscope-cli status"
echo "  3. Monitor Traffic:    netscope-cli traffic"
echo "  4. Sniff Packets:      netscope-cli sniff --count 50"
echo
