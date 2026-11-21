Name:           netscope
Version:        0.2.0
Release:        1%{?dist}
Summary:        Linux Network Intelligence and Forensic Telemetry Desktop Application

License:        MIT
URL:            https://github.com/akmhabibulislam/netscope
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust
BuildRequires:  cargo
BuildRequires:  gcc
BuildRequires:  pkgconfig
BuildRequires:  gtk4-devel >= 4.10
BuildRequires:  libadwaita-devel >= 1.4
BuildRequires:  sqlite-devel >= 3.35
BuildRequires:  libcap-devel
BuildRequires:  desktop-file-utils

Requires:       gtk4 >= 4.10
Requires:       libadwaita >= 1.4
Requires:       sqlite-libs >= 3.35
Requires:       iproute
Requires:       libcap

# Avoid stripping debug symbols with external tool if Cargo handles it
%global debug_package %{nil}

%description
NetScope is a modern, cross-distribution Linux network intelligence, forensic
packet analysis, and connection monitoring suite. Built in Rust with GTK4,
Libadwaita, and SQLite, NetScope provides deep protocol dissection (IPv4, IPv6,
TCP, UDP, ARP, 802.1Q VLAN), connection lifecycle inspection via /proc netlink,
offline threat intelligence matching (abuse.ch Feodo & URLhaus), and safe,
transactional emergency firewall killswitch controls.

%prep
%autosetup -n %{name}-%{version}

%build
cargo build --release --workspace

%install
rm -rf %{buildroot}

# Install application binaries
install -D -p -m 0755 target/release/netscope %{buildroot}%{_bindir}/netscope-gui
ln -sf netscope-gui %{buildroot}%{_bindir}/netscope
install -D -p -m 0755 target/release/netscope-cli %{buildroot}%{_bindir}/netscope-cli

# Install desktop entry
install -D -p -m 0644 resources/netscope.desktop %{buildroot}%{_datadir}/applications/netscope.desktop

# Install application icon
install -D -p -m 0644 resources/icons/netscope.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/netscope.svg

# Install documentation
install -d %{buildroot}%{_docdir}/%{name}
install -p -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md

%check
desktop-file-validate %{buildroot}%{_datadir}/applications/netscope.desktop

%post
/usr/bin/update-desktop-database &> /dev/null || :
/bin/touch --no-create %{_datadir}/icons/hicolor &>/dev/null || :
/usr/bin/gtk4-update-icon-cache %{_datadir}/icons/hicolor &>/dev/null || :
# Grant packet capture capabilities to netscope-cli without requiring root
/usr/sbin/setcap cap_net_raw,cap_net_admin=eip %{_bindir}/netscope-cli 2>/dev/null || :

%postun
/usr/bin/update-desktop-database &> /dev/null || :
/bin/touch --no-create %{_datadir}/icons/hicolor &>/dev/null || :
/usr/bin/gtk4-update-icon-cache %{_datadir}/icons/hicolor &>/dev/null || :

%files
%license LICENSE-MIT
%doc README.md
%{_bindir}/netscope
%{_bindir}/netscope-gui
%{_bindir}/netscope-cli
%{_datadir}/applications/netscope.desktop
%{_datadir}/icons/hicolor/scalable/apps/netscope.svg

%changelog
* Fri Nov 20 2026 NetScope Contributors <dev@netscope.internal> - 0.2.0-1
- Hardened firewall rollback and backend consistency (nftables + iptables)
- Added continuous interface-bound CLI traffic monitoring
- Expanded threat intelligence with domain validation and normalization
- Native Fedora Workstation RPM packaging and desktop integration
