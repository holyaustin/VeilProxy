# Linux / macOS convenience targets (Windows: see docs/INSTALL.md for the equivalent commands)
PY ?= python3
VENV = .venv
BIN = $(VENV)/bin

.PHONY: install rust test rust-test doctor serve tui demo selftest clean
install:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[dev]"
	$(BIN)/pip install "maturin>=1.5,<2"
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
