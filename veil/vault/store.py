"""SQLite storage. Holds ONLY ciphertext, keyed pseudonym tags and redacted audit records."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Callable

_SCHEMA = """
CREATE TABLE IF NOT EXISTS items(
  session TEXT NOT NULL, placeholder TEXT NOT NULL, kind TEXT NOT NULL,
  tag TEXT NOT NULL, ciphertext BLOB NOT NULL, created_at REAL NOT NULL,
  PRIMARY KEY(session, placeholder));
CREATE UNIQUE INDEX IF NOT EXISTS items_tag ON items(session, tag);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, session TEXT NOT NULL,
  model TEXT, stream INTEGER, status INTEGER, latency_ms INTEGER,
  detections TEXT, outbound TEXT, upstream_id TEXT, upstream_model TEXT,
  usage TEXT, note TEXT);
"""


class Store:
    def __init__(self, path: Path | str):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._db.executescript(_SCHEMA)
            self._db.commit()
        if str(path) != ":memory:":
            try:
                Path(path).chmod(0o600)
            except OSError:
                pass

    def get_or_create_item(
        self, session: str, kind: str, tag: str, make_ciphertext: Callable[[str], bytes]
    ) -> tuple[str, bool]:
        """Return (placeholder, created). Atomic per tag; numbering is per (session, kind)."""
        with self._lock:
            row = self._db.execute(
                "SELECT placeholder FROM items WHERE session=? AND tag=?", (session, tag)
            ).fetchone()
            if row:
                return row["placeholder"], False
            n = self._db.execute(
                "SELECT COUNT(*) c FROM items WHERE session=? AND kind=?", (session, kind)
            ).fetchone()["c"]
            ph = f"[{kind}_{n + 1}]"
            self._db.execute(
                "INSERT INTO items VALUES(?,?,?,?,?,?)",
                (session, ph, kind, tag, make_ciphertext(ph), time.time()),
            )
            self._db.commit()
            return ph, True

    def get_ciphertext(self, session: str, placeholder: str) -> bytes | None:
        with self._lock:
            row = self._db.execute(
                "SELECT ciphertext FROM items WHERE session=? AND placeholder=?",
                (session, placeholder),
            ).fetchone()
        return bytes(row["ciphertext"]) if row else None

    def list_items(self, session: str | None = None) -> list[dict]:
        q = "SELECT session, placeholder, kind, created_at FROM items"
        args: tuple = ()
        if session:
            q += " WHERE session=?"
            args = (session,)
        with self._lock:
            return [dict(r) for r in self._db.execute(q + " ORDER BY created_at", args)]

    def add_audit(self, **f) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO audit(ts,session,model,stream,status,latency_ms,detections,"
                "outbound,upstream_id,upstream_model,usage,note) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    time.time(), f["session"], f.get("model"), int(bool(f.get("stream"))),
                    f.get("status"), f.get("latency_ms"),
                    json.dumps(f.get("detections", [])), f.get("outbound"),
                    f.get("upstream_id"), f.get("upstream_model"),
                    json.dumps(f.get("usage")) if f.get("usage") else None, f.get("note"),
                ),
            )
            self._db.commit()
            return int(cur.lastrowid)

    def list_audit(self, limit: int = 20, session: str | None = None) -> list[dict]:
        q = "SELECT * FROM audit"
        args: list = []
        if session:
            q += " WHERE session=?"
            args.append(session)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = [dict(r) for r in self._db.execute(q, args)]
        for r in rows:
            r["detections"] = json.loads(r["detections"] or "[]")
            r["usage"] = json.loads(r["usage"]) if r["usage"] else None
        return rows

    def wipe_session(self, session: str) -> int:
        with self._lock:
            c = self._db.execute("DELETE FROM items WHERE session=?", (session,)).rowcount
            self._db.commit()
            return c

    def close(self) -> None:
        with self._lock:
            self._db.close()
