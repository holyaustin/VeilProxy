# Linux / macOS convenience targets (Windows: see docs/INSTALL.md for the equivalent commands)
# Prefer python3.12 (tested); override with: make install PY=python3.13
PY ?= $(shell command -v python3.12 || command -v python3)
VENV = .venv
BIN = $(VENV)/bin

# Tolerate slow / flaky networks (long timeouts, many retries, no HTTP/2 multiplexing for cargo)
export PIP_DEFAULT_TIMEOUT = 180
export PIP_RETRIES = 15
export CARGO_HTTP_TIMEOUT = 600
export CARGO_NET_RETRY = 15
export CARGO_HTTP_MULTIPLEXING = false

.PHONY: install venv deps rust rust-test test doctor serve tui demo selftest clean
# Run the steps separately if your connection is bad: make venv && make deps && make rust
install: venv deps rust
venv:
	test -x $(BIN)/python || $(PY) -m venv $(VENV)
deps: venv
	$(BIN)/python -m pip install -e ".[dev]" "maturin>=1.5,<2"
rust: deps
	cd core && ../$(BIN)/maturin develop --release
rust-test:
	cd core && cargo test
test:
	$(BIN)/python -m pytest -q
doctor:
	$(BIN)/veil doctor
serve:
	$(BIN)/veil serve
tui:
	$(BIN)/veil tui
demo:
	$(BIN)/veil demo
selftest:
	$(BIN)/veil selftest
clean:
	rm -rf $(VENV) core/target .pytest_cache .hypothesis *.egg-info
