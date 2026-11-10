# Installation, extraction and testing (new machine)

> **Python version:** use **3.12** (tested). 3.10 is only the declared minimum and was not tested.
> On Ubuntu 22.04 the stock `python3` is 3.10 — the bootstrap script installs 3.12 from the deadsnakes PPA.

Total time: ~15-25 minutes (the Rust build is the slow part). Python >= 3.10, Rust (stable), Node 22/24 are needed.

## 0. Extract
```bash
unzip veilproxy.zip && cd veilproxy          # Windows: right-click > Extract All, then open a terminal in the folder
```

## 1. Prerequisites
**Ubuntu/Debian** — `bash scripts/bootstrap_ubuntu.sh`, or manually:
```bash
sudo apt-get update && sudo apt-get install -y git curl build-essential pkg-config libssl-dev python3 python3-venv python3-pip unzip
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source ~/.cargo/env
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash - && sudo apt-get install -y nodejs
```
**macOS** — `bash scripts/bootstrap_macos.sh` (installs Xcode CLT, Homebrew, Python 3.12, Node 24, rustup).

**Windows 10/11** — elevated PowerShell: `./scripts/bootstrap_windows.ps1` (Git, Python 3.12, Node LTS, Rustup,
VS 2022 Build Tools with the C++ workload). Reopen the terminal afterwards.

Verify: `python3 --version` (>=3.10) · `cargo --version` · `node -v` (22.x or 24+; **not 23**).
> Ubuntu's apt `cargo` is old; use rustup. If you are stuck with an old cargo (<1.85) the bundled `core/Cargo.lock` already pins compatible crates.

## 2. Install VeilProxy
Linux/macOS: `make install`  
Windows (PowerShell):
```powershell
py -3.12 -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install --upgrade pip ; pip install -e ".[dev]" ; pip install "maturin>=1.5,<2"
cd core ; maturin develop --release ; cd ..
```
Activate the venv in every new terminal: `source .venv/bin/activate` (Windows: `.\.venv\Scripts\Activate.ps1`).

## 3. Run the test suites (do this before anything else)
```bash
make rust-test        # cd core && cargo test           -> 7 passed
make test             # pytest -q                       -> 60 passed
veil selftest         # offline leak test               -> "leaked to provider: 0"
veil demo             # offline before/after demo (MOCK provider)
```

## 4. Install and start OmniRoute
```bash
npm install -g omniroute
omniroute                       # dashboard http://localhost:20128, API http://localhost:20128/v1
```
(or `docker run -p 20128:20128 diegosouzapw/omniroute`). In the dashboard: add a provider account/API key
(a free-tier provider is fine), create an **endpoint API key**, and note a model id (`veil models` lists them).

## 5. Configure
```bash
cp .env.example .env            # Windows: copy .env.example .env
# edit: OMNIROUTE_API_KEY=<endpoint key>   VEIL_DEFAULT_MODEL=<provider/model>
veil init                       # creates the 3-of-5 vault in ~/.veilproxy
veil doctor                     # every required line must be green
```

## 6. Run (4 terminals, venv active in each)
| Terminal | Command | Purpose |
|---|---|---|
| A | `veil custodians --approve 1,2,3` | five local custodians; 1-3 approve, 4-5 deny (demo) |
| B | `veil serve` | the gateway on :8787 |
| C | `veil tui` | the UI: type `/unlock`, then chat |
| D (optional) | `mitmweb --mode reverse:http://127.0.0.1:20128 --listen-port 8888 --web-port 8081` | evidence view; then set `OMNIROUTE_BASE_URL=http://127.0.0.1:8888/v1` in `.env` and restart B |

Smoke test with the real model: `veil demo --live`.

## 7. Acceptance checklist
- [ ] `cargo test` 7 passed, `pytest` all passed, `veil selftest` leaks = 0
- [ ] `veil doctor` all required checks green (crypto backend = rust)
- [ ] `/shards <2 shards>` fails, 3 shards (or custodians) unlock
- [ ] TUI pane ② shows only placeholders; pane ① shows real values
- [ ] mitmweb shows the outbound request with placeholders only
- [ ] `/lock` then a prompt -> "Vault is locked"

## Troubleshooting
| Symptom | Fix |
|---|---|
| `veil_core` import fails / doctor says python backend | `cd core && maturin develop --release` inside the venv |
| `feature edition2024 is required` | upgrade Rust: `rustup update stable` |
| doctor: OmniRoute unreachable | start `omniroute`; check `OMNIROUTE_BASE_URL` ends in `/v1` |
| 401 from OmniRoute | set `OMNIROUTE_API_KEY` to an endpoint key from the dashboard |
| 423 vault locked | `/unlock` in the TUI (custodians must be running) |
| 422 leak_blocked | working as designed; add a rule or allowlist in `config/rules.example.yaml` |
| Node 23 refuses OmniRoute | use Node 22 LTS or 24 |
| apt: `python3-venv : Depends: python3 (= 3.10.6-1~22.04)` | stale/mismatched apt lists. Run `sudo apt-get update`, or skip apt Python: install 3.12 via deadsnakes (`bootstrap_ubuntu.sh`) or `uv` (`curl -LsSf https://astral.sh/uv/install.sh \| sh`, then `uv venv --python 3.12 .venv`) |
