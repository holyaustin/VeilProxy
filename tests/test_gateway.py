import json
import sqlite3

import httpx
import pytest

from tests.conftest import make_env
from veil.gateway.redact import Redactor

EMAIL, CARD, KEY = "bob@example.com", "4111 1111 1111 1111", "sk-proj-abcdefghijklmnopqrstuvwx1234"
PROMPT = f"Email {EMAIL}, charge card {CARD}, and use key {KEY} please"


def sent_text(env):
    return json.dumps(env.log, ensure_ascii=False)


async def test_locked_vault_blocks_everything(env):
    r = await env.chat(PROMPT)
    assert r.status_code == 423 and r.json()["error"]["type"] == "vault_locked"
    assert env.log == []  # nothing reached the provider


async def test_threshold_unlock_two_shards_fail_three_succeed(env):
    r = await env.unlock(2)
    assert r.status_code == 403 and "insufficient" in r.json()["error"]
    r = await env.unlock(3)
    assert r.status_code == 200 and r.json()["ok"]
    st = (await env.client.get("/admin/status", headers=env.admin)).json()
    assert st["unlocked"] and st["k"] == 3 and st["n"] == 5


async def test_nonstream_round_trip_provider_sees_only_placeholders(env):
    await env.unlock()
    r = await env.chat(PROMPT)
    assert r.status_code == 200
    # provider (fake OmniRoute) received placeholders only
    blob = sent_text(env)
    for secret in (EMAIL, CARD, KEY, "4111"):
        assert secret not in blob
    assert "[EMAIL_1]" in blob and "[CARD_1]" in blob and "[APIKEY_1]" in blob
    # user gets the real values back
    text = r.json()["choices"][0]["message"]["content"]
    assert EMAIL in text and CARD in text and KEY in text and "[" not in text
    assert r.headers["x-veil-redactions"] == "3"


async def test_streaming_rehydrates_across_chunk_boundaries(env):
    await env.unlock()
    r = await env.chat(PROMPT, stream=True)
    assert r.status_code == 200
    out, done = "", False
    for line in r.text.splitlines():
        if line.startswith("data:") and line[5:].strip() != "[DONE]":
            d = json.loads(line[5:])
            out += d["choices"][0]["delta"].get("content") or ""
        if "[DONE]" in line:
            done = True
    assert done and EMAIL in out and CARD in out and KEY in out and "[EMAIL" not in out
    assert EMAIL not in sent_text(env)


async def test_placeholders_are_stable_across_turns_and_dedup(env):
    await env.unlock()
    await env.chat(f"first {EMAIL}", session="s1")
    await env.chat(f"again {EMAIL} and other carol@example.org", session="s1")
    sent = [json.dumps(b) for b in env.log]
    assert "[EMAIL_1]" in sent[0] and "[EMAIL_1]" in sent[1] and "[EMAIL_2]" in sent[1]
    items = (await env.client.get("/admin/items", params={"session": "s1"}, headers=env.admin)).json()
    assert [i["placeholder"] for i in items] == ["[EMAIL_1]", "[EMAIL_2]"]
    assert all("value" not in i and "ciphertext" not in i for i in items)


async def test_sessions_are_isolated(env):
    await env.unlock()
    await env.chat(f"x {EMAIL}", session="alice")
    await env.chat("y carol@example.org", session="bob")
    both = [json.dumps(b) for b in env.log]
    assert "[EMAIL_1]" in both[0] and "[EMAIL_1]" in both[1]  # numbering restarts per session
    # bob's placeholder must not decrypt alice's value
    r = await env.chat("what is [EMAIL_1]?", session="bob")
    assert EMAIL not in r.text


async def test_database_and_audit_contain_no_plaintext(env):
    await env.unlock()
    await env.chat(PROMPT)
    env.app.state.ctx.store._db.commit()
    raw = open(env.settings.db_path, "rb").read()
    for secret in (EMAIL, CARD, KEY):
        assert secret.encode() not in raw
    audit = (await env.client.get("/admin/audit", headers=env.admin)).json()
    assert audit and audit[0]["status"] == 200 and audit[0]["usage"]["total_tokens"] == 12
    assert audit[0]["upstream_id"] == "chatcmpl-test"
    for secret in (EMAIL, CARD, KEY):
        assert secret not in audit[0]["outbound"]
    assert {d["kind"] for d in audit[0]["detections"]} == {"EMAIL", "CARD", "APIKEY"}


async def test_fail_closed_guard_blocks_if_redaction_breaks(env, monkeypatch):
    await env.unlock()
    monkeypatch.setattr(Redactor, "redact_text", lambda self, t: t)  # simulate a redactor bug
    r = await env.chat(PROMPT)
    assert r.status_code == 422 and r.json()["error"]["type"] == "leak_blocked"
    assert env.log == []


async def test_lock_then_requests_fail(env):
    await env.unlock()
    assert (await env.chat("hi")).status_code == 200
    await env.client.post("/admin/lock", headers=env.admin)
    assert (await env.chat("hi")).status_code == 423


async def test_upstream_error_passthrough_and_unreachable(env, tmp_path):
    await env.unlock()
    r = await env.chat("FORCE_500")
    assert r.status_code == 500 and r.json()["error"]["message"] == "boom"

    def boom(request):
        raise httpx.ConnectError("refused")

    e2 = make_env(tmp_path / "b")
    e2.app.state.ctx.client = httpx.AsyncClient(transport=httpx.MockTransport(boom), base_url="http://x/v1/")
    await e2.unlock()
    r = await e2.chat("hello")
    assert r.status_code == 502 and "unreachable" in r.json()["error"]["message"]
    await e2.client.aclose()


async def test_sensitive_kinds_route_to_local_model(tmp_path):
    e = make_env(tmp_path, local_model="ollama/llama3")
    await e.unlock()
    await e.chat(f"card {CARD}")
    await e.chat(f"mail {EMAIL}")
    assert e.log[0]["model"] == "ollama/llama3"      # CARD is high-sensitivity
    assert e.log[1]["model"] == "fake/model-a"        # EMAIL is not
    await e.client.aclose()


async def test_auth_models_and_validation(tmp_path):
    e = make_env(tmp_path, client_key="client-secret")
    assert (await e.client.get("/v1/models")).status_code == 401
    r = await e.client.get("/v1/models", headers={"Authorization": "Bearer client-secret"})
    assert r.status_code == 200 and "fake/model-a" in [m["id"] for m in r.json()["data"]]
    assert (await e.client.get("/admin/status")).status_code == 401
    bad = await e.client.post("/v1/chat/completions", json={"x": 1}, headers={"Authorization": "Bearer client-secret"})
    assert bad.status_code == 400
    bad = await e.client.post("/v1/chat/completions", json={"messages": []},
                              headers={"Authorization": "Bearer client-secret", "X-Veil-Session": "bad session!"})
    assert bad.status_code == 400
    await e.client.aclose()


async def test_secrets_in_multipart_and_tool_content_are_redacted(env):
    await env.unlock()
    body = {"model": "fake/model-a", "messages": [
        {"role": "user", "content": [{"type": "text", "text": f"mail {EMAIL}"}]},
        {"role": "assistant", "content": None, "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "send", "arguments": json.dumps({"to": EMAIL, "k": KEY})}}]},
    ]}
    r = await env.client.post("/v1/chat/completions", json=body)
    assert r.status_code == 200
    assert EMAIL not in sent_text(env) and KEY not in sent_text(env)
