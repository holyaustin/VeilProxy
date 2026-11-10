"""Crypto backend selector: Rust core (`veil_core`) when available, else pure Python.

Set VEIL_CRYPTO_BACKEND=rust|python|auto (default auto).
"""
from __future__ import annotations

import importlib
import os
from types import ModuleType


def get_backend(name: str = "auto") -> tuple[ModuleType, str]:
    name = name.lower()
    if name in ("auto", "rust"):
        try:
            return importlib.import_module("veil_core"), "rust"
        except ImportError:
            if name == "rust":
                raise RuntimeError(
                    "VEIL_CRYPTO_BACKEND=rust but veil_core is not installed. "
                    "Run: pip install maturin && cd core && maturin develop --release"
                ) from None
    from . import pure

    return pure, "python"


_mod, BACKEND = get_backend(os.environ.get("VEIL_CRYPTO_BACKEND", "auto"))
KeyHolder = _mod.KeyHolder
generate_shares = _mod.generate_shares
split_secret = _mod.split_secret
combine_shares = _mod.combine_shares
