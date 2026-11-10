"""Thin async client the TUI (and demo) use to talk to the VeilProxy gateway."""
from __future__ import annotations

import json
from typing import AsyncIterator

import httpx


class GatewayError(Exception):
    pass


def _msg(r: httpx.Response) -> str:
    try:
        j = r.json()
        e = j.get("error", j) if isinstance(j, dict) else j
        return e.get("message", str(e)) if isinstance(e, dict) else str(e)
    except Exception:
        return f"HTTP {r.status_code}: {r.text[:200]}"


class GatewayClient:
    def __init__(self, base_url: str, admin_token: str, client_key: str = "",
                 transport: httpx.AsyncBaseTransport | None = None, timeout: float = 120.0):
        self.http = httpx.AsyncClient(base_url=base_url, transport=transport, timeout=timeout)
        self.admin = {"X-Veil-Admin": admin_token}
        self.auth = {"Authorization": f"Bearer {client_key}"} if client_key else {}

    async def aclose(self) -> None:
        await self.http.aclose()

    async def _get(self, path: str, admin: bool = True, **params):
        try:
            r = await self.http.get(path, params=params, headers=self.admin if admin else self.auth)
        except httpx.HTTPError as e:
            raise GatewayError(f"cannot reach VeilProxy gateway: {e}") from e
        if r.status_code >= 400:
            raise GatewayError(_msg(r))
        return r.json()

    async def status(self) -> dict:
        return await self._get("/admin/status")

    async def audit(self, limit: int = 1, session: str | None = None) -> list[dict]:
        p = {"limit": limit}
        if session:
            p["session"] = session
        return await self._get("/admin/audit", **p)

    async def items(self, session: str | None = None) -> list[dict]:
        return await self._get("/admin/items", **({"session": session} if session else {}))

    async def models(self) -> list[str]:
        j = await self._get("/v1/models", admin=False)
        return [m["id"] for m in j.get("data", [])]

    async def unlock(self, shards: list[str] | None = None) -> dict:
        try:
            r = await self.http.post("/admin/unlock", json={"shards": shards or []}, headers=self.admin, timeout=120)
        except httpx.HTTPError as e:
            raise GatewayError(f"cannot reach VeilProxy gateway: {e}") from e
        return r.json()

    async def lock(self) -> dict:
        r = await self.http.post("/admin/lock", headers=self.admin)
        return r.json()

    async def chat_stream(self, messages: list[dict], model: str, session: str) -> AsyncIterator[str]:
        body = {"model": model, "messages": messages, "stream": True}
        if not model:
            body.pop("model")
        headers = {**self.auth, "X-Veil-Session": session}
        try:
            async with self.http.stream("POST", "/v1/chat/completions", json=body, headers=headers) as r:
                if r.status_code != 200:
                    await r.aread()
                    raise GatewayError(_msg(r))
                async for line in r.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    payload = line[5:].strip()
                    if payload == "[DONE]":
                        return
                    try:
                        d = json.loads(payload)
                    except ValueError:
                        continue
                    for ch in d.get("choices") or []:
                        t = (ch.get("delta") or {}).get("content")
                        if t:
                            yield t
        except httpx.HTTPError as e:
            raise GatewayError(f"connection problem: {e}") from e
