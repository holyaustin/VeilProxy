"""Settings (env / .env) and the on-disk vault config."""
from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


def _split(v: str) -> list[str]:
    return [x.strip().upper() for x in v.split(",") if x.strip()]


@dataclass
class Settings:
    home: Path
    omniroute_base_url: str = "http://localhost:20128/v1"
    omniroute_api_key: str = ""
    default_model: str = ""
    host: str = "127.0.0.1"
    port: int = 8787
    client_key: str = ""            # optional bearer key that clients must send to VeilProxy
    idle_lock_seconds: int = 900    # auto-lock the vault after this much inactivity (0 = never)
    upstream_timeout: float = 120.0
    nlp: bool = False               # enable Presidio/spaCy name+place detection
    local_model: str = ""           # model alias to route to when high-sensitivity data is found
    local_only_kinds: list[str] = field(
        default_factory=lambda: ["PRIVATEKEY", "CARD", "SSN", "IBAN"]
    )
    rules_file: Path | None = None

    @property
    def db_path(self) -> Path:
        return self.home / "vault.db"

    @property
    def config_path(self) -> Path:
        return self.home / "config.json"

    @property
    def custodian_dir(self) -> Path:
        return self.home / "custodians"


def load_settings(home: str | os.PathLike | None = None) -> Settings:
    load_dotenv(Path.cwd() / ".env")
    h = Path(home or os.environ.get("VEIL_HOME") or Path.home() / ".veilproxy").expanduser()
    load_dotenv(h / ".env")
    env = os.environ.get
    rules = env("VEIL_RULES_FILE")
    s = Settings(
        home=h,
        omniroute_base_url=env("OMNIROUTE_BASE_URL", "http://localhost:20128/v1").rstrip("/"),
        omniroute_api_key=env("OMNIROUTE_API_KEY", ""),
        default_model=env("VEIL_DEFAULT_MODEL", ""),
        host=env("VEIL_HOST", "127.0.0.1"),
        port=int(env("VEIL_PORT", "8787")),
        client_key=env("VEIL_CLIENT_KEY", ""),
        idle_lock_seconds=int(env("VEIL_IDLE_LOCK_SECONDS", "900")),
        upstream_timeout=float(env("VEIL_UPSTREAM_TIMEOUT", "120")),
        nlp=env("VEIL_NLP", "0").lower() in ("1", "true", "yes"),
        local_model=env("VEIL_LOCAL_MODEL", ""),
        rules_file=Path(rules).expanduser() if rules else None,
    )
    if env("VEIL_LOCAL_ONLY_KINDS"):
        s.local_only_kinds = _split(env("VEIL_LOCAL_ONLY_KINDS", ""))
    return s


@dataclass
class VaultConfig:
    n: int
    k: int
    key_check: str
    admin_token: str
    custodians: list[dict]  # [{"id": 1, "port": 8801, "token": "..."}]

    @staticmethod
    def new(n: int, k: int, key_check: str, base_port: int = 8801) -> "VaultConfig":
        return VaultConfig(
            n=n,
            k=k,
            key_check=key_check,
            admin_token=secrets.token_urlsafe(32),
            custodians=[
                {"id": i, "port": base_port + i - 1, "token": secrets.token_urlsafe(24)}
                for i in range(1, n + 1)
            ],
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.__dict__, indent=2))
        try:
            path.chmod(0o600)
        except OSError:
            pass

    @staticmethod
    def load(path: Path) -> "VaultConfig":
        if not path.exists():
            raise FileNotFoundError(f"Vault not initialised ({path}). Run: veil init")
        return VaultConfig(**json.loads(path.read_text()))
