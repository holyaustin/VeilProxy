"""VaultManager: threshold unlock, idle auto-lock, and encrypt/decrypt helpers.

The master key lives only inside the crypto backend's KeyHolder (Rust memory when the Rust
core is used). Python never receives it.
"""
from __future__ import annotations

import asyncio
import time

import httpx

from .. import crypto
from ..config import Settings, VaultConfig


class VaultLocked(Exception):
    pass


class VaultManager:
    def __init__(self, settings: Settings, vcfg: VaultConfig | None, keyholder=None):
        self.settings = settings
        self.vcfg = vcfg
        self.holder = keyholder if keyholder is not None else crypto.KeyHolder()
        self.last_used = time.monotonic()
        self.last_unlock: dict = {}

    # -- state -----------------------------------------------------------------
    @property
    def unlocked(self) -> bool:
        return self.holder.is_unlocked()

    def status(self) -> dict:
        idle = None
        if self.unlocked and self.settings.idle_lock_seconds:
            idle = max(0, int(self.settings.idle_lock_seconds - (time.monotonic() - self.last_used)))
        return {
            "initialised": self.vcfg is not None,
            "unlocked": self.unlocked,
            "n": self.vcfg.n if self.vcfg else None,
            "k": self.vcfg.k if self.vcfg else None,
            "backend": crypto.BACKEND,
            "auto_lock_in": idle,
            "last_unlock": self.last_unlock,
        }

    def touch(self) -> None:
        self.last_used = time.monotonic()

    def lock(self) -> None:
        self.holder.lock()
        self.last_unlock = {}

    def ensure_unlocked(self) -> None:
        if not self.unlocked:
            raise VaultLocked("Vault is locked. Unlock it with threshold shards (veil tui -> /unlock).")
        self.touch()

    # -- unlock ----------------------------------------------------------------
    def unlock_with_shares(self, shares: list[str]) -> dict:
        if not self.vcfg:
            return {"ok": False, "error": "vault not initialised (run: veil init)"}
        try:
            ok = self.holder.unlock(list(shares), self.vcfg.key_check)
        except ValueError as e:
            self.last_unlock = {"ok": False, "error": str(e), "method": "shares"}
            return self.last_unlock
        if ok:
            self.touch()
            self.last_unlock = {"ok": True, "method": "shares", "shares_used": len(shares)}
        else:
            self.last_unlock = {
                "ok": False, "method": "shares",
                "error": "shares did not reconstruct the master key (wrong or mixed shares)",
            }
        return self.last_unlock

    async def unlock_with_custodians(self, timeout: float = 90.0) -> dict:
        if not self.vcfg:
            return {"ok": False, "error": "vault not initialised (run: veil init)"}
        k = self.vcfg.k
        results: dict[int, dict] = {}
        shards: dict[int, str] = {}

        async def ask(c: dict) -> tuple[int, str, str | None]:
            url = f"http://127.0.0.1:{c['port']}/release"
            try:
                async with httpx.AsyncClient(timeout=timeout) as cl:
                    r = await cl.post(
                        url, headers={"Authorization": f"Bearer {c['token']}"},
                        json={"requester": "veilproxy", "reason": "unlock vault"},
                    )
                if r.status_code == 200:
                    return c["id"], "approved", r.json()["shard"]
                return c["id"], "denied" if r.status_code == 403 else f"error {r.status_code}", None
            except httpx.ConnectError:
                return c["id"], "unreachable", None
            except httpx.TimeoutException:
                return c["id"], "timeout", None

        tasks = [asyncio.create_task(ask(c)) for c in self.vcfg.custodians]
        pending = set(tasks)
        try:
            while pending and len(shards) < k:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    cid, state, shard = t.result()
                    results[cid] = {"state": state}
                    if shard:
                        shards[cid] = shard
        finally:
            for t in pending:
                t.cancel()
            for t in pending:
                results.setdefault(self.vcfg.custodians[tasks.index(t)]["id"], {"state": "not asked"})
        out = {"method": "custodians", "custodians": results, "approved": len(shards), "needed": k}
        if len(shards) < k:
            out.update(ok=False, error=f"only {len(shards)} of {k} required custodians approved")
        else:
            out.update(self.unlock_with_shares(list(shards.values())))
            out["method"] = "custodians"
        self.last_unlock = out
        return out

    # -- crypto helpers ----------------------------------------------------------
    @staticmethod
    def _aad(session: str, placeholder: str) -> bytes:
        return f"{session}|{placeholder}".encode()

    def encrypt_item(self, session: str, placeholder: str, value: str) -> bytes:
        self.ensure_unlocked()
        return bytes(self.holder.encrypt(session, value.encode(), self._aad(session, placeholder)))

    def decrypt_item(self, session: str, placeholder: str, blob: bytes) -> str:
        self.ensure_unlocked()
        return bytes(self.holder.decrypt(session, blob, self._aad(session, placeholder))).decode()

    def tag(self, session: str, value: str) -> str:
        self.ensure_unlocked()
        return self.holder.tag(session, value.encode())

    async def watchdog(self, period: float = 5.0) -> None:
        while True:
            await asyncio.sleep(period)
            lim = self.settings.idle_lock_seconds
            if lim and self.unlocked and time.monotonic() - self.last_used > lim:
                self.lock()
