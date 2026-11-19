# Contributing to NetScope

Thank you for your interest in contributing to **NetScope**! We welcome bug reports, feature suggestions, architectural improvements, and code contributions from engineers, security researchers, and Linux enthusiasts.

---

## 🧭 Code of Conduct

We are committed to providing a welcoming, inclusive, and harassment-free environment for all contributors. Please treat everyone with respect, professionalism, and empathy.

---

## 🛠️ Development Setup

### Prerequisites

Ensure you have the following installed on your Linux development machine:

- **Rust Toolchain**: `rustup` with the latest stable compiler (1.80+ or Rust 2024 edition).
- **GTK4 & Libadwaita**:
  - **Arch / CachyOS**: `sudo pacman -S gtk4 libadwaita sqlite libcap pkgconf`
  - **Fedora**: `sudo dnf install gtk4-devel libadwaita-devel sqlite-devel libcap-devel pkgconf`
  - **Ubuntu / Debian**: `sudo apt install libgtk-4-dev libadwaita-1-dev libsqlite3-dev libcap2-bin pkg-config`

### Building the Workspace

```bash
# Clone your fork
git clone https://github.com/<your-username>/netscope.git
cd netscope

# Check code formatting and run clippy
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings

# Build the entire workspace
cargo build

# Run automated tests
cargo test --workspace
```

---

## 🌿 Git Workflow & Branching

1. **Fork the repository** on GitHub.
2. **Create a feature branch**:
   ```bash
   git checkout -b feat/your-feature-name
   # or for bug fixes:
   git checkout -b fix/issue-description
   ```
3. **Commit with Conventional Commits format**:
   - `feat(...)`: A new user-facing or technical feature
   - `fix(...)`: A bug fix
   - `docs(...)`: Documentation additions or refinements
   - `refactor(...)`: Code changes that neither fix a bug nor add a feature
   - `perf(...)`: Performance optimization
   - `test(...)`: Adding or updating test suites
4. **Push your branch & submit a Pull Request**:
   Clearly explain the problem being solved, architectural rationale, and provide verification evidence (CLI logs or UI screenshots).

---

## 📐 Architecture & Coding Standards

1. **Safety & Privacy First**:
   - Do not add background network calls or analytics telemetry.
   - All network intelligence, IoC checking, and diagnostics must prioritize offline, local-first operation.
2. **Graceful Degradation**:
   - The application must remain functional for standard non-root desktop users.
   - If a privileged operation (e.g. `AF_PACKET` raw capture or `ss -K` socket termination) lacks permissions, fail with an informative warning or fallback rather than panicking.
3. **Error Handling**:
   - Library crates (`netscope-*`) must use strongly-typed errors via `thiserror`.
   - Applications (`netscope`, `netscope-cli`) may use `anyhow` for top-level context propagation.

---

## 🧪 Reporting Bugs & Requesting Features

- **Bug Reports**: Open an issue detailing your Linux distribution, desktop environment (Wayland/X11, GNOME/KDE/Hyprland), kernel version (`uname -r`), and reproduction steps.
- **Security Vulnerabilities**: Please review our [SECURITY.md](SECURITY.md) for responsible disclosure procedures before opening a public issue.
