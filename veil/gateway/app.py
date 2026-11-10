"""VeilProxy gateway: an OpenAI-compatible endpoint that redacts before forwarding to OmniRoute."""
from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import re
import time
from dataclasses import dataclass

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .. import __version__, crypto
from ..config import Settings, VaultConfig, load_settings
from ..detect import Detector
from ..vault.manager import VaultLocked, VaultManager
from ..vault.store import Store
from .redact import LeakBlocked, Redactor, StreamRehydrator, check_outbound, map_strings, rehydrate_text

SESSION_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


@dataclass
class Ctx:
    settings: Settings
    store: Store
    vault: VaultManager
    detector: Detector
    client: httpx.AsyncClient


def _err(status: int, message: str, typ: str) -> JSONResponse:
    return JSONResponse({"error": {"message": message, "type": typ}}, status_code=status)


def create_app(
    settings: Settings | None = None,
    *,
    upstream_transport: httpx.AsyncBaseTransport | None = None,
    vault: VaultManager | None = None,
    store: Store | None = None,
) -> FastAPI:
    settings = settings or load_settings()
    try:
        vcfg = VaultConfig.load(settings.config_path)
    except FileNotFoundError:
        vcfg = None
    store = store or Store(settings.db_path)
    vault = vault or VaultManager(settings, vcfg)
    headers = {"Content-Type": "application/json"}
    if settings.omniroute_api_key:
        headers["Authorization"] = f"Bearer {settings.omniroute_api_key}"
    client = httpx.AsyncClient(
        base_url=settings.omniroute_base_url.rstrip("/") + "/",
        headers=headers,
        timeout=httpx.Timeout(settings.upstream_timeout, connect=10.0),
        transport=upstream_transport,
    )
    ctx = Ctx(settings, store, vault, Detector(settings.rules_file, nlp=settings.nlp), client)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        task = asyncio.create_task(ctx.vault.watchdog())
        yield
        task.cancel()
        await ctx.client.aclose()

    app = FastAPI(title="VeilProxy", version=__version__, lifespan=lifespan)
    app.state.ctx = ctx

    # ---------------------------------------------------------------- auth helpers
    def client_auth(authorization: str | None = Header(default=None)) -> None:
        if ctx.settings.client_key:
            got = (authorization or "").removeprefix("Bearer ").strip()
            if not hmac.compare_digest(got, ctx.settings.client_key):
                raise HTTPException(401, "invalid client key")

    def admin_auth(x_veil_admin: str | None = Header(default=None)) -> None:
        if not ctx.vault.vcfg or not hmac.compare_digest(x_veil_admin or "", ctx.vault.vcfg.admin_token):
            raise HTTPException(401, "invalid admin token")

    def session_of(request: Request, body: dict | None = None) -> str:
        s = request.headers.get("x-veil-session") or (body or {}).get("user") or "default"
        if not isinstance(s, str) or not SESSION_RE.match(s):
            raise HTTPException(400, "invalid session id (use 1-64 chars of A-Za-z0-9_.:-)")
        return s

    def resolver(session: str):
        def resolve(ph: str) -> str | None:
            blob = ctx.store.get_ciphertext(session, ph)
            if blob is None:
                return None
            try:
                return ctx.vault.decrypt_item(session, ph, blob)
            except Exception:
                return None

        return resolve

    # ---------------------------------------------------------------- public API
    @app.get("/health")
    async def health():
        return {"ok": True, "version": __version__, "vault_unlocked": ctx.vault.unlocked, "crypto": crypto.BACKEND}

    @app.get("/v1/models", dependencies=[Depends(client_auth)])
    async def models():
        try:
            r = await ctx.client.get("models")
            return JSONResponse(r.json(), status_code=r.status_code)
        except httpx.HTTPError as e:
            return _err(502, f"OmniRoute unreachable at {ctx.settings.omniroute_base_url}: {e}", "upstream_unreachable")

    @app.post("/v1/chat/completions", dependencies=[Depends(client_auth)])
    async def chat(request: Request):
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return _err(400, "request body is not valid JSON", "invalid_request")
        if not isinstance(body, dict) or not isinstance(body.get("messages"), list):
            return _err(400, "'messages' array is required", "invalid_request")
        session = session_of(request, body)
        t0 = time.monotonic()
        try:
            ctx.vault.ensure_unlocked()
            red = Redactor(ctx.detector, ctx.vault, ctx.store, session)
            out = red.redact_payload(body)
            if not out.get("model"):
                out["model"] = ctx.settings.default_model
            if not out["model"]:
                return _err(400, "no model given and VEIL_DEFAULT_MODEL is not set", "invalid_request")
            note = None
            kinds = {d.kind for d in red.detections}
            if ctx.settings.local_model and kinds & set(ctx.settings.local_only_kinds):
                out["model"] = ctx.settings.local_model
                note = f"routed to local model ({', '.join(sorted(kinds & set(ctx.settings.local_only_kinds)))})"
            check_outbound(out, red.values, ctx.detector)
        except VaultLocked as e:
            return _err(423, str(e), "vault_locked")
        except LeakBlocked as e:
            return _err(422, f"VeilProxy blocked the request (fail-closed): {e}", "leak_blocked")

        stream = bool(out.get("stream"))
        dets = [d.__dict__ for d in red.detections]
        outbound = json.dumps(out, ensure_ascii=False)
        resolve = resolver(session)
        audit = dict(session=session, model=out["model"], stream=stream, detections=dets,
                     outbound=outbound, note=note)
        hdr = {"X-Veil-Redactions": str(len(dets)), "X-Veil-Session": session}

        try:
            req = ctx.client.build_request("POST", "chat/completions", json=out)
            resp = await ctx.client.send(req, stream=stream)
        except httpx.HTTPError as e:
            ctx.store.add_audit(**{**audit, "note": f"upstream error: {e}"}, status=502,
                                latency_ms=int((time.monotonic() - t0) * 1000))
            return _err(502, f"OmniRoute unreachable at {ctx.settings.omniroute_base_url}: {e}", "upstream_unreachable")

        if resp.status_code >= 400:
            raw = await resp.aread() if stream else resp.content
            await resp.aclose()
            ctx.store.add_audit(**audit, status=resp.status_code, latency_ms=int((time.monotonic() - t0) * 1000))
            try:
                payload = json.loads(raw)
            except ValueError:
                payload = {"error": {"message": raw.decode(errors="replace")[:500], "type": "upstream_error"}}
            return JSONResponse(payload, status_code=resp.status_code, headers=hdr)

        if not stream:
            data = resp.json()
            data = map_strings(data, lambda s: rehydrate_text(s, resolve))
            ctx.store.add_audit(
                **audit, status=resp.status_code, latency_ms=int((time.monotonic() - t0) * 1000),
                upstream_id=data.get("id"), upstream_model=data.get("model"), usage=data.get("usage"),
            )
            return JSONResponse(data, headers=hdr)

        async def gen():
            rh: dict = {}
            meta: dict = {}
            last: dict = {}

            def get(idx, key):
                if (idx, key) not in rh:
                    rh[(idx, key)] = StreamRehydrator(resolve)
                return rh[(idx, key)]

            def flush_into(delta: dict, idx: int):
                for (i, key), r in rh.items():
                    if i != idx:
                        continue
                    tail = r.flush()
                    if not tail:
                        continue
                    if isinstance(key, str):
                        delta[key] = (delta.get(key) or "") + tail
                    else:
                        tcs = delta.setdefault("tool_calls", [])
                        tcs.append({"index": key[1], "function": {"arguments": tail}})

            try:
                async for line in resp.aiter_lines():
                    if not line.startswith("data:"):
                        yield line + "\n"
                        continue
                    payload = line[5:].strip()
                    if payload == "[DONE]":
                        for idx in sorted({i for i, _ in rh}):
                            delta: dict = {}
                            flush_into(delta, idx)
                            if delta:
                                tail = {"id": last.get("id"), "object": "chat.completion.chunk",
                                        "model": last.get("model"),
                                        "choices": [{"index": idx, "delta": delta, "finish_reason": None}]}
                                yield "data: " + json.dumps(tail, ensure_ascii=False) + "\n\n"
                        yield "data: [DONE]\n\n"
                        continue
                    try:
                        chunk = json.loads(payload)
                    except ValueError:
                        yield line + "\n"
                        continue
                    last = chunk
                    meta.setdefault("id", chunk.get("id"))
                    meta.setdefault("model", chunk.get("model"))
                    if chunk.get("usage"):
                        meta["usage"] = chunk["usage"]
                    for ch in chunk.get("choices") or []:
                        idx = ch.get("index", 0)
                        delta = ch.get("delta") or {}
                        for f in ("content", "reasoning_content", "reasoning"):
                            if isinstance(delta.get(f), str):
                                delta[f] = get(idx, f).feed(delta[f])
                        for tc in delta.get("tool_calls") or []:
                            fn = tc.get("function") or {}
                            if isinstance(fn.get("arguments"), str):
                                fn["arguments"] = get(idx, ("tc", tc.get("index", 0))).feed(fn["arguments"])
                        if ch.get("finish_reason"):
                            flush_into(delta, idx)
                    yield "data: " + json.dumps(chunk, ensure_ascii=False) + "\n\n"
            finally:
                await resp.aclose()
                ctx.store.add_audit(
                    **audit, status=resp.status_code, latency_ms=int((time.monotonic() - t0) * 1000),
                    upstream_id=meta.get("id"), upstream_model=meta.get("model"), usage=meta.get("usage"),
                )

        return StreamingResponse(gen(), media_type="text/event-stream", headers=hdr)

    # ---------------------------------------------------------------- admin API
    @app.get("/admin/status", dependencies=[Depends(admin_auth)])
    async def a_status():
        s = ctx.settings
        return {
            **ctx.vault.status(),
            "upstream": s.omniroute_base_url,
            "upstream_key_configured": bool(s.omniroute_api_key),
            "default_model": s.default_model,
            "local_model": s.local_model,
            "version": __version__,
        }

    @app.post("/admin/unlock", dependencies=[Depends(admin_auth)])
    async def a_unlock(request: Request):
        body = await request.json()
        if body.get("shards"):
            res = ctx.vault.unlock_with_shares([str(x) for x in body["shards"]])
        else:
            res = await ctx.vault.unlock_with_custodians()
        return JSONResponse(res, status_code=200 if res.get("ok") else 403)

    @app.post("/admin/lock", dependencies=[Depends(admin_auth)])
    async def a_lock():
        ctx.vault.lock()
        return {"ok": True, "unlocked": False}

    @app.get("/admin/audit", dependencies=[Depends(admin_auth)])
    async def a_audit(limit: int = 20, session: str | None = None):
        return ctx.store.list_audit(min(limit, 200), session)

    @app.get("/admin/items", dependencies=[Depends(admin_auth)])
    async def a_items(session: str | None = None):
        return ctx.store.list_items(session)

    @app.post("/admin/detect", dependencies=[Depends(admin_auth)])
    async def a_detect(request: Request):
        text = (await request.json()).get("text", "")
        return [{"kind": m.kind, "start": m.start, "end": m.end, "length": m.end - m.start}
                for m in ctx.detector.find(text)]

    @app.delete("/admin/session/{sid}", dependencies=[Depends(admin_auth)])
    async def a_wipe(sid: str):
        return {"deleted": ctx.store.wipe_session(sid)}

    return app


def app_factory() -> FastAPI:  # uvicorn --factory target
    return create_app()
