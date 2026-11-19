# NetScope 2.0 Installation & Package Management

## System Dependencies

### Arch Linux / CachyOS / EndeavourOS / Manjaro
```bash
sudo pacman -S rust cargo gtk4 libadwaita sqlite iproute2 iw
```

### Fedora / RHEL / CentOS
```bash
sudo dnf install rust cargo gtk4-devel libadwaita-devel sqlite-devel iproute iw
```

### Ubuntu / Debian / Linux Mint / Pop!_OS
```bash
sudo apt install cargo rustc libgtk-4-dev libadwaita-1-dev libsqlite3-dev iproute2 iw
```

## Compiling From Source
```bash
git clone https://github.com/netscope/netscope.git
cd netscope
cargo build --release
```

Run the GUI:
```bash
./target/release/netscope
```

Run the CLI Companion:
```bash
./target/release/netscope-cli --help
```
