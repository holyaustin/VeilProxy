import socket

import pytest

from veil import crypto
from veil.config import Settings, VaultConfig
from veil.vault.custodian import build_server, serve_in_thread
from veil.vault.manager import VaultManager
import json


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def setup(tmp_path, modes):
    shares, chk = crypto.generate_shares(5, 3)
    vcfg = VaultConfig.new(5, 3, chk)
    servers = []
    for c, mode, shard in zip(vcfg.custodians, modes, shares):
        c["port"] = free_port()
        f = tmp_path / f"s{c['id']}.json"
        f.write_text(json.dumps({"id": c["id"], "shard": shard}))
        if mode != "down":
            srv = build_server(c["id"], f, c["port"], c["token"], mode, log=lambda *_: None)
            serve_in_thread(srv)
            servers.append(srv)
    mgr = VaultManager(Settings(home=tmp_path, idle_lock_seconds=0), vcfg)
    return mgr, servers


async def test_three_of_five_custodians_approve_unlocks(tmp_path):
    mgr, servers = setup(tmp_path, ["auto", "auto", "auto", "deny", "deny"])
    try:
        res = await mgr.unlock_with_custodians(timeout=10)
        assert res["ok"] and mgr.unlocked and res["approved"] == 3
    finally:
        [s.shutdown() for s in servers]


async def test_two_of_five_is_not_enough(tmp_path):
    mgr, servers = setup(tmp_path, ["auto", "auto", "deny", "deny", "down"])
    try:
        res = await mgr.unlock_with_custodians(timeout=10)
        assert not res["ok"] and not mgr.unlocked
        states = {k: v["state"] for k, v in res["custodians"].items()}
        assert states[3] == "denied" and states[5] == "unreachable"
    finally:
        [s.shutdown() for s in servers]


async def test_custodian_rejects_wrong_token(tmp_path):
    import httpx
    mgr, servers = setup(tmp_path, ["auto"] * 5)
    try:
        c = mgr.vcfg.custodians[0]
        async with httpx.AsyncClient() as cl:
            r = await cl.post(f"http://127.0.0.1:{c['port']}/release", headers={"Authorization": "Bearer nope"}, json={})
        assert r.status_code == 401 and "shard" not in r.text
    finally:
        [s.shutdown() for s in servers]
