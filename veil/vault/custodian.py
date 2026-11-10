"""Custodian: a tiny separate process that holds ONE Shamir shard and releases it only when approved.

Modes:  ask  - the operator at this terminal must type y (the realistic threshold flow)
        auto - approve every request (demo / CI)
        deny - refuse every request (demo of a custodian that says no)
"""
from __future__ import annotations

import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def _make_handler(cid: int, token: str, shard: str, mode: str, prompt_lock: threading.Lock, log):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence default logging
            pass

        def _send(self, code: int, obj: dict):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authed(self) -> bool:
            got = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            return hmac.compare_digest(got, token)

        def do_GET(self):
            if self.path == "/status":
                self._send(200, {"id": cid, "mode": mode, "has_shard": True})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            if self.path != "/release":
                return self._send(404, {"error": "not found"})
            if not self._authed():
                return self._send(401, {"error": "bad token"})
            n = int(self.headers.get("Content-Length") or 0)
            try:
                req = json.loads(self.rfile.read(n) or b"{}")
            except json.JSONDecodeError:
                req = {}
            who = req.get("requester", "unknown")
            if mode == "auto":
                approved = True
            elif mode == "deny":
                approved = False
            else:
                with prompt_lock:
                    try:
                        ans = input(f"\n[custodian {cid}] '{who}' requests your shard. Approve? [y/N] ")
                    except EOFError:
                        ans = "n"
                approved = ans.strip().lower() in ("y", "yes")
            log(f"custodian {cid}: request from {who} -> {'APPROVED' if approved else 'DENIED'}")
            if approved:
                self._send(200, {"id": cid, "shard": shard})
            else:
                self._send(403, {"id": cid, "error": "denied by custodian"})

    return H


def build_server(cid: int, shard_file: Path, port: int, token: str, mode: str = "ask",
                 host: str = "127.0.0.1", log=print) -> ThreadingHTTPServer:
    shard = json.loads(Path(shard_file).read_text())["shard"]
    handler = _make_handler(cid, token, shard, mode, threading.Lock(), log)
    return ThreadingHTTPServer((host, port), handler)


def serve_in_thread(server: ThreadingHTTPServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t
