from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from veil import crypto
from veil.config import Settings, VaultConfig
from veil.gateway.app import create_app
from veil.mock_upstream import build_fake_upstream

PH = re.compile(r"\[[A-Z][A-Z0-9]*_\d+\]")


@dataclass
class Env:
    settings: Settings
    app: FastAPI
    shares: list
    log: list
    admin: dict
    client: httpx.AsyncClient = None
    aclose: list = field(default_factory=list)

    async def unlock(self, n=3):
        r = await self.client.post("/admin/unlock", json={"shards": self.shares[:n]}, headers=self.admin)
        return r

    async def chat(self, content, stream=False, session=None, **extra):
        headers = {"X-Veil-Session": session} if session else {}
        body = {"model": "fake/model-a", "messages": [{"role": "user", "content": content}], "stream": stream, **extra}
        return await self.client.post("/v1/chat/completions", json=body, headers=headers)


def make_env(tmp_path, backend="auto", **settings_kw) -> Env:
    mod, _ = crypto.get_backend(backend)
    shares, check = mod.generate_shares(5, 3)
    home = tmp_path / "home"
    s = Settings(home=home, omniroute_base_url="http://upstream/v1", omniroute_api_key="up-key",
                 default_model="fake/model-a", idle_lock_seconds=0, **settings_kw)
    vcfg = VaultConfig.new(5, 3, check)
    vcfg.save(s.config_path)
    log: list = []
    upstream = build_fake_upstream(log)
    app = create_app(s, upstream_transport=httpx.ASGITransport(app=upstream))
    app.state.ctx.vault.holder = mod.KeyHolder()
    env = Env(s, app, shares, log, {"X-Veil-Admin": vcfg.admin_token})
    env.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://veil")
    return env


@pytest.fixture(params=["python", "rust"])
def backend(request):
    try:
        crypto.get_backend(request.param)
    except RuntimeError:
        pytest.skip("rust backend not built")
    return request.param


@pytest.fixture
async def env(tmp_path):
    e = make_env(tmp_path)
    yield e
    await e.client.aclose()
