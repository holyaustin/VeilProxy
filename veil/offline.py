"""In-process pipeline against the mock upstream (no network, no OmniRoute). Used by `veil demo --offline`
and `veil selftest`. Output is clearly labelled as mock: it proves the redaction pipeline, not an LLM."""
from __future__ import annotations

import tempfile
from pathlib import Path

import httpx

from . import crypto
from .config import Settings, VaultConfig
from .gateway.app import create_app
from .mock_upstream import build_fake_upstream


def build_offline(home: Path | None = None, n: int = 5, k: int = 3):
    home = home or Path(tempfile.mkdtemp(prefix="veil-offline-"))
    shares, check = crypto.generate_shares(n, k)
    s = Settings(home=home, omniroute_base_url="http://mock/v1", default_model="mock/echo-a", idle_lock_seconds=0)
    vcfg = VaultConfig.new(n, k, check)
    vcfg.save(s.config_path)
    log: list = []
    app = create_app(s, upstream_transport=httpx.ASGITransport(app=build_fake_upstream(log)))
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://veil")
    return app, client, shares, {"X-Veil-Admin": vcfg.admin_token}, log
