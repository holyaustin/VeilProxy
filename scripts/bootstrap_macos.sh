#!/usr/bin/env bash
# Fresh macOS machine (Homebrew) -> VeilProxy prerequisites.
set -euo pipefail
xcode-select -p >/dev/null 2>&1 || xcode-select --install
command -v brew >/dev/null || /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install python@3.12 git node@24 rustup-init
[ -d "$HOME/.cargo" ] || rustup-init -y
echo "Prerequisites installed. Open a new terminal, then: make install && make test"
