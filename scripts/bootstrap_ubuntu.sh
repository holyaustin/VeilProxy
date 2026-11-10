#!/usr/bin/env bash
# Fresh Ubuntu/Debian machine -> working VeilProxy dev environment (+ optional OmniRoute).
set -euo pipefail
sudo apt-get update
sudo apt-get install -y git curl build-essential pkg-config libssl-dev python3 python3-venv python3-pip unzip
# Rust (rustup gives a current toolchain)
if ! command -v cargo >/dev/null; then curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; fi
source "$HOME/.cargo/env"
# Node 24 LTS (for OmniRoute): OmniRoute supports Node >=22 <23 or >=24 <27
if ! command -v node >/dev/null || ! node -v | grep -Eq '^v(22|24|25|26)\.'; then
  curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
  sudo apt-get install -y nodejs
fi
echo "Prerequisites installed. Next: make install && make test   (see docs/INSTALL.md)"
