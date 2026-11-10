"""`veil` command line: init, custodian(s), serve, tui, demo, doctor, selftest, models, mock-omniroute."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

from . import __version__, crypto
from .config import VaultConfig, load_settings

DEMO_PROMPT = (
    "Please draft a short email to {email}. Mention that the invoice is paid with card {card}, "
    "and that our deploy key is {key}. My phone is {phone}."
)
DEMO_VALUES = {
    "email": "ada.obi@example.com",
    "card": "4111 1111 1111 1111",
    "key": "sk-proj-Q8x2LmN4vB7cR1tY9uZ3aW5eD6fG0hJk",
    "phone": "08031234567",
}

G, R, Y, B, X = "\033[92m", "\033[91m", "\033[93m", "\033[1m", "\033[0m"
if not sys.stdout.isatty():
    G = R = Y = B = X = ""


def _settings(a):
    return load_settings(getattr(a, "home", None))


# ------------------------------------------------------------------ init
def cmd_init(a) -> int:
    s = _settings(a)
    if s.config_path.exists() and not a.force:
        print(f"{R}Vault already initialised at {s.home}. Use --force to replace it (this destroys old data).{X}")
        return 1
    if not (2 <= a.threshold <= a.shares <= 255):
        print(f"{R}need 2 <= threshold <= shares <= 255{X}")
        return 1
    shares, check = crypto.generate_shares(a.shares, a.threshold)
    cfg = VaultConfig.new(a.shares, a.threshold, check, a.base_port)
    cfg.save(s.config_path)
    s.custodian_dir.mkdir(parents=True, exist_ok=True)
    for c, sh in zip(cfg.custodians, shares):
        f = s.custodian_dir / f"shard_{c['id']}.json"
        f.write_text(json.dumps({"id": c["id"], "shard": sh}))
        try:
            f.chmod(0o600)
        except OSError:
            pass
    if s.db_path.exists() and a.force:
        s.db_path.unlink()
    print(f"{G}✔ Vault initialised{X} at {s.home}  ({a.threshold}-of-{a.shares}, crypto backend: {crypto.BACKEND})")
    print(f"  The master key was generated inside the crypto core and is NOT stored anywhere.")
    print(f"  Shards: {s.custodian_dir}/shard_<id>.json  -- for real use, MOVE each file to a different")
    print(f"  machine/USB/person and run `veil custodian --id N --shard-file PATH` there.")
    if a.print_shares:
        print("\nShards (shown once):")
        for sh in shares:
            print("  " + sh)
    return 0


# ------------------------------------------------------------------ custodians
def cmd_custodian(a) -> int:
    from .vault.custodian import build_server

    s = _settings(a)
    cfg = VaultConfig.load(s.config_path)
    c = next((x for x in cfg.custodians if x["id"] == a.id), None)
    if not c:
        print(f"{R}no custodian with id {a.id}{X}")
        return 1
    f = Path(a.shard_file) if a.shard_file else s.custodian_dir / f"shard_{a.id}.json"
    port = a.port or c["port"]
    srv = build_server(a.id, f, port, c["token"], a.mode, log=lambda m: print(f"{Y}{m}{X}", flush=True))
    print(f"custodian {a.id} listening on 127.0.0.1:{port}  mode={a.mode}  shard={f}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_custodians(a) -> int:
    s = _settings(a)
    cfg = VaultConfig.load(s.config_path)
    approve = {int(x) for x in a.approve.split(",")} if a.approve else {c["id"] for c in cfg.custodians}
    procs = []
    base = [sys.executable, "-m", "veil.cli", "custodian"]
    if a.home:
        base = [sys.executable, "-m", "veil.cli", "--home", a.home, "custodian"]
    for c in cfg.custodians:
        mode = "auto" if c["id"] in approve else "deny"
        procs.append(subprocess.Popen(base + ["--id", str(c["id"]), "--mode", mode]))
    print(f"{G}started {len(procs)} custodians{X}; auto-approving: {sorted(approve)}; others deny. Ctrl+C to stop.")
    try:
        for p in procs:
            p.wait()
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs:
            p.terminate()
    return 0


# ------------------------------------------------------------------ serve / tui / mock
def cmd_serve(a) -> int:
    import uvicorn

    s = _settings(a)
    if a.home:
        os.environ["VEIL_HOME"] = a.home
    if not s.omniroute_api_key:
        print(f"{Y}! OMNIROUTE_API_KEY is empty. Fine if OmniRoute has REQUIRE_API_KEY off; otherwise set it in .env{X}")
    print(f"{B}VeilProxy{X} on http://{a.host or s.host}:{a.port or s.port}/v1  ->  OmniRoute {s.omniroute_base_url}")
    uvicorn.run("veil.gateway.app:app_factory", factory=True, host=a.host or s.host,
                port=a.port or s.port, log_level="info")
    return 0


def cmd_tui(a) -> int:
    from .tui.app import VeilApp
    from .tui.client import GatewayClient

    s = _settings(a)
    cfg = VaultConfig.load(s.config_path)
    gc = GatewayClient(f"http://{a.host or s.host}:{a.port or s.port}", cfg.admin_token, s.client_key)
    VeilApp(gc, model=a.model or s.default_model, session=a.session).run()
    return 0


def cmd_mock(a) -> int:
    import uvicorn

    print(f"{Y}MOCK OmniRoute (echo server, not an LLM) on http://127.0.0.1:{a.port}/v1{X}")
    uvicorn.run("veil.mock_upstream:app_factory", factory=True, host="127.0.0.1", port=a.port, log_level="warning")
    return 0


# ------------------------------------------------------------------ models
def cmd_models(a) -> int:
    import httpx

    s = _settings(a)
    h = {"Authorization": f"Bearer {s.omniroute_api_key}"} if s.omniroute_api_key else {}
    try:
        r = httpx.get(s.omniroute_base_url + "/models", headers=h, timeout=15)
        r.raise_for_status()
    except Exception as e:
        print(f"{R}cannot list models from {s.omniroute_base_url}: {e}{X}")
        return 1
    ids = sorted(m["id"] for m in r.json().get("data", []))
    print(f"{len(ids)} models available via OmniRoute:")
    for i in ids[: a.limit]:
        print("  " + i)
    if len(ids) > a.limit:
        print(f"  ... and {len(ids) - a.limit} more (use --limit)")
    return 0


# ------------------------------------------------------------------ demo
def _print_demo(typed: str, wire: str, seen: str, meta: str = "") -> None:
    print(f"\n{B}① YOU TYPED (stays on this machine){X}\n  {typed}")
    print(f"\n{B}② PROVIDER RECEIVED{X}  {meta}\n  {Y}{wire}{X}")
    print(f"\n{B}③ YOU SEE (rehydrated locally){X}\n  {G}{seen}{X}\n")


async def _demo_offline() -> int:
    from .offline import build_offline

    print(f"{Y}OFFLINE demo against a MOCK provider (an echo server, not an LLM). Use --live for real OmniRoute.{X}")
    app, client, shares, admin, log = build_offline()
    await client.post("/admin/unlock", json={"shards": shares[:2]}, headers=admin)
    r = await client.post("/admin/unlock", json={"shards": shares[:2]}, headers=admin)
    print(f"{R}2 shards -> {r.json().get('error')}{X}")
    r = await client.post("/admin/unlock", json={"shards": shares[:3]}, headers=admin)
    print(f"{G}3 shards -> unlocked: {r.json().get('ok')}{X}")
    typed = DEMO_PROMPT.format(**DEMO_VALUES)
    resp = await client.post("/v1/chat/completions", json={"model": "mock/echo-a",
                             "messages": [{"role": "user", "content": typed}]})
    seen = resp.json()["choices"][0]["message"]["content"]
    _print_demo(typed, log[-1]["messages"][0]["content"], seen)
    leaked = [v for v in DEMO_VALUES.values() if v in json.dumps(log)]
    print(f"{G if not leaked else R}leak check: {'no secret reached the provider' if not leaked else leaked}{X}")
    await client.aclose()
    return 1 if leaked else 0


async def _demo_live(a) -> int:
    from .tui.client import GatewayClient, GatewayError

    s = _settings(a)
    cfg = VaultConfig.load(s.config_path)
    gc = GatewayClient(f"http://{s.host}:{s.port}", cfg.admin_token, s.client_key)
    try:
        st = await gc.status()
        if not st["unlocked"]:
            print(f"{Y}vault locked -> asking custodians (approve in their terminals)…{X}")
            res = await gc.unlock()
            if not res.get("ok"):
                print(f"{R}unlock failed: {res.get('error')}{X}")
                return 1
        typed = DEMO_PROMPT.format(**DEMO_VALUES)
        out = ""
        async for piece in gc.chat_stream([{"role": "user", "content": typed}], a.model or s.default_model, "demo"):
            out += piece
        row = (await gc.audit(1, "demo"))[0]
        wire = json.loads(row["outbound"])["messages"][0]["content"]
        meta = f"(model {row['model']}, upstream id {row['upstream_id']}, status {row['status']})"
        _print_demo(typed, wire, out, meta)
        leaked = [v for v in DEMO_VALUES.values() if v in row["outbound"]]
        print(f"{G if not leaked else R}leak check: {'no secret reached the provider' if not leaked else leaked}{X}")
        return 1 if leaked else 0
    except GatewayError as e:
        print(f"{R}{e}{X}")
        return 1
    finally:
        await gc.aclose()


def cmd_demo(a) -> int:
    return asyncio.run(_demo_live(a) if a.live else _demo_offline())


# ------------------------------------------------------------------ selftest
def cmd_selftest(a) -> int:
    import random
    import string

    from .offline import build_offline

    async def run() -> int:
        app, client, shares, admin, log = build_offline()
        await client.post("/admin/unlock", json={"shards": shares[:3]}, headers=admin)
        rng = random.Random(7)
        A = string.ascii_letters + string.digits
        secrets_: list[str] = []
        for i in range(a.n):
            sec = [f"{''.join(rng.choices(string.ascii_lowercase, k=8))}@example.org",
                   "sk-proj-" + "".join(rng.choices(A, k=40)), "AKIA" + "".join(rng.choices(string.ascii_uppercase, k=16))]
            secrets_ += sec
            r = await client.post("/v1/chat/completions", json={"model": "mock/echo-a", "stream": i % 3 == 0,
                                  "messages": [{"role": "user", "content": "notes: " + " | ".join(sec)}]})
            if r.status_code != 200:
                print(f"{R}request {i} failed: {r.text}{X}")
                return 1
        blob = json.dumps(log)
        leaked = [x for x in secrets_ if x in blob]
        print(f"{G if not leaked else R}{a.n} prompts, {len(secrets_)} secrets -> leaked to provider: {len(leaked)}{X}")
        await client.aclose()
        return 1 if leaked else 0

    return asyncio.run(run())


# ------------------------------------------------------------------ doctor
def cmd_doctor(a) -> int:
    import httpx

    s = _settings(a)
    bad = 0

    def line(ok, msg, warn=False):
        nonlocal bad
        mark = f"{G}✔{X}" if ok else (f"{Y}!{X}" if warn else f"{R}✖{X}")
        bad += 0 if ok or warn else 1
        print(f" {mark} {msg}")

    print(f"{B}VeilProxy doctor{X}  v{__version__}")
    line(sys.version_info >= (3, 10), f"Python {sys.version.split()[0]} (need >= 3.10)")
    line(crypto.BACKEND == "rust", f"crypto backend: {crypto.BACKEND}" +
         ("" if crypto.BACKEND == "rust" else "  (build Rust core: cd core && maturin develop --release)"), warn=True)
    try:
        cfg = VaultConfig.load(s.config_path)
        line(True, f"vault initialised: {cfg.k}-of-{cfg.n} at {s.home}")
        shards = sorted(s.custodian_dir.glob("shard_*.json")) if s.custodian_dir.exists() else []
        line(bool(shards), f"{len(shards)} local shard file(s)", warn=True)
    except FileNotFoundError:
        cfg = None
        line(False, "vault not initialised  -> run: veil init")
    line(bool(s.omniroute_api_key), "OMNIROUTE_API_KEY set", warn=True)
    line(bool(s.default_model), f"VEIL_DEFAULT_MODEL = {s.default_model or '(unset; clients must send a model)'}", warn=True)
    h = {"Authorization": f"Bearer {s.omniroute_api_key}"} if s.omniroute_api_key else {}
    try:
        r = httpx.get(s.omniroute_base_url + "/models", headers=h, timeout=8)
        n = len(r.json().get("data", [])) if r.status_code == 200 else 0
        line(r.status_code == 200, f"OmniRoute {s.omniroute_base_url}  -> HTTP {r.status_code}, {n} models")
    except Exception as e:
        line(False, f"OmniRoute unreachable at {s.omniroute_base_url}: {type(e).__name__}  (is `omniroute` running?)")
    try:
        r = httpx.get(f"http://{s.host}:{s.port}/health", timeout=3).json()
        line(True, f"gateway up on :{s.port} (vault {'unlocked' if r['vault_unlocked'] else 'locked'})")
    except Exception:
        line(False, f"gateway not running on :{s.port}  (start: veil serve)", warn=True)
    if cfg:
        up = 0
        for c in cfg.custodians:
            try:
                httpx.get(f"http://127.0.0.1:{c['port']}/status", timeout=1)
                up += 1
            except Exception:
                pass
        line(up >= cfg.k, f"{up}/{cfg.n} custodians reachable (need {cfg.k})", warn=True)
    try:
        import presidio_analyzer  # noqa: F401
        line(True, "Presidio installed (VEIL_NLP=1 enables name/place detection)")
    except ImportError:
        line(True, "Presidio not installed (optional: pip install '.[nlp]')", warn=False)
    import shutil
    line(bool(shutil.which("mitmweb")), "mitmproxy (mitmweb) on PATH — optional, for the demo video", warn=True)
    print(f"\n{G+'All required checks passed.'+X if not bad else R+str(bad)+' required check(s) failed.'+X}")
    return 1 if bad else 0


# ------------------------------------------------------------------ main
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="veil", description="VeilProxy + ShardKey")
    p.add_argument("--home", help="state directory (default ~/.veilproxy or $VEIL_HOME)")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("init", help="generate master key, split it, write shard files")
    i.add_argument("--shares", type=int, default=5)
    i.add_argument("--threshold", type=int, default=3)
    i.add_argument("--base-port", type=int, default=8801)
    i.add_argument("--print-shares", action="store_true")
    i.add_argument("--force", action="store_true")
    i.set_defaults(fn=cmd_init)

    c = sub.add_parser("custodian", help="run ONE shard custodian")
    c.add_argument("--id", type=int, required=True)
    c.add_argument("--mode", choices=["ask", "auto", "deny"], default="ask")
    c.add_argument("--port", type=int)
    c.add_argument("--shard-file")
    c.set_defaults(fn=cmd_custodian)

    cs = sub.add_parser("custodians", help="demo: start all custodians locally (auto-approve some, deny the rest)")
    cs.add_argument("--approve", help="comma-separated ids that auto-approve, e.g. 1,2,3 (default: all)")
    cs.set_defaults(fn=cmd_custodians)

    sv = sub.add_parser("serve", help="start the gateway")
    sv.add_argument("--host")
    sv.add_argument("--port", type=int)
    sv.set_defaults(fn=cmd_serve)

    t = sub.add_parser("tui", help="open the terminal UI")
    t.add_argument("--host")
    t.add_argument("--port", type=int)
    t.add_argument("--model")
    t.add_argument("--session", default="tui")
    t.set_defaults(fn=cmd_tui)

    d = sub.add_parser("demo", help="scripted before/after demo")
    d.add_argument("--live", action="store_true", help="use the running gateway + real OmniRoute")
    d.add_argument("--model")
    d.set_defaults(fn=cmd_demo)

    sub.add_parser("doctor", help="check the installation").set_defaults(fn=cmd_doctor)
    m = sub.add_parser("models", help="list OmniRoute models")
    m.add_argument("--limit", type=int, default=40)
    m.set_defaults(fn=cmd_models)
    st = sub.add_parser("selftest", help="offline leak test (mock provider)")
    st.add_argument("-n", type=int, default=200)
    st.set_defaults(fn=cmd_selftest)
    mk = sub.add_parser("mock-omniroute", help="run a MOCK OpenAI-compatible server for offline testing")
    mk.add_argument("--port", type=int, default=20128)
    mk.set_defaults(fn=cmd_mock)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
