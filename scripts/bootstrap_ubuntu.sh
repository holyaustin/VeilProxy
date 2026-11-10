#!/usr/bin/env bash
# Fresh Ubuntu/Debian machine -> VeilProxy prerequisites, using Python 3.12 (the tested version).
set -euo pipefail
sudo apt-get update
sudo apt-get install -y git curl build-essential pkg-config libssl-dev unzip software-properties-common

# --- Python 3.12 (+ venv). On Ubuntu < 24.04 the stock python3 is older, so use the deadsnakes PPA.
if ! command -v python3.12 >/dev/null; then
  if [ "$(lsb_release -si 2>/dev/null)" = "Ubuntu" ]; then
    sudo add-apt-repository -y ppa:deadsnakes/ppa
    sudo apt-get update
  fi
  sudo apt-get install -y python3.12 python3.12-venv python3.12-dev
fi
python3.12 -m venv --help >/dev/null   # fails loudly if the venv module is missing

# --- Rust (rustup gives a current toolchain)
if ! command -v cargo >/dev/null; then curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; fi
source "$HOME/.cargo/env"

# --- Node 24 LTS (for OmniRoute; supports Node >=22 <23 or >=24 <27)
if ! command -v node >/dev/null || ! node -v | grep -Eq '^v(22|24|25|26)\.'; then
  curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
  sudo apt-get install -y nodejs
fi
echo "Prerequisites installed ($(python3.12 --version), $(cargo --version), node $(node -v))."
echo "Next:  source ~/.cargo/env && make install     (the Makefile auto-selects python3.12)"
