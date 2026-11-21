#!/usr/bin/env bash
# NetScope Fedora RPM Build Script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RPM_WORK_DIR="${REPO_ROOT}/target/rpmbuild"
VERSION="0.2.0"
PKG_NAME="netscope"

echo "[*] Preparing NetScope ${VERSION} Fedora RPM build workspace..."

# Ensure rpmbuild directory tree exists
mkdir -p "${RPM_WORK_DIR}"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

# Copy SPEC file
cp "${SCRIPT_DIR}/netscope.spec" "${RPM_WORK_DIR}/SPECS/"

# Create source archive excluding build artifacts
echo "[*] Packaging source tarball ${PKG_NAME}-${VERSION}.tar.gz..."
tar --exclude="./target" \
    --exclude="./.git" \
    --exclude="./packaging/arch/pkg" \
    --exclude="./packaging/arch/src" \
    --transform "s,^\.,${PKG_NAME}-${VERSION}," \
    -czf "${RPM_WORK_DIR}/SOURCES/${PKG_NAME}-${VERSION}.tar.gz" \
    -C "${REPO_ROOT}" .

echo "[*] Executing rpmbuild..."
if command -v rpmbuild &>/dev/null; then
    rpmbuild --define "_topdir ${RPM_WORK_DIR}" -ba "${RPM_WORK_DIR}/SPECS/netscope.spec"
    echo "[+] RPM package successfully built!"
    find "${RPM_WORK_DIR}/RPMS" -type f -name "*.rpm"
else
    echo "[!] 'rpmbuild' tool not found on host. Use a Fedora environment or GitHub Actions to complete RPM binary compilation."
    echo "[*] Source archive staged at: ${RPM_WORK_DIR}/SOURCES/${PKG_NAME}-${VERSION}.tar.gz"
fi
