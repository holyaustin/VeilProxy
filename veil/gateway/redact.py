"""Redaction, rehydration (incl. streaming-safe) and the outbound leak guard."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from ..detect import Detector
from ..detect.engine import PLACEHOLDER_RE
from ..vault.manager import VaultManager
from ..vault.store import Store

# Structural JSON keys whose string values are never user content.
SKIP_KEYS = {"model", "role", "type", "object", "id", "tool_call_id", "finish_reason", "stream"}


class LeakBlocked(Exception):
    """Raised (fail-closed) when plaintext sensitive data is still present in an outbound payload."""


def map_strings(obj: Any, fn: Callable[[str], str], skip: set[str] = SKIP_KEYS, _key: str | None = None) -> Any:
    if isinstance(obj, str):
        return obj if _key in skip else fn(obj)
    if isinstance(obj, list):
        return [map_strings(x, fn, skip, _key) for x in obj]
    if isinstance(obj, dict):
        return {k: map_strings(v, fn, skip, k) for k, v in obj.items()}
    return obj


def iter_strings(obj: Any, skip: set[str] = SKIP_KEYS, _key: str | None = None, _path: str = "$"):
    """Yield (path, string) for every user-content string leaf (structural keys like `model` are skipped,
    exactly as in redaction, so the guard and the redactor always look at the same data)."""
    if isinstance(obj, str):
        if _key not in skip:
            yield _path, obj
    elif isinstance(obj, list):
        for i, x in enumerate(obj):
            yield from iter_strings(x, skip, _key, f"{_path}[{i}]")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from iter_strings(v, skip, k, f"{_path}.{k}")


@dataclass
class Detection:
    kind: str
    placeholder: str
    length: int
    new: bool


@dataclass
class Redactor:
    detector: Detector
    vault: VaultManager
    store: Store
    session: str
    detections: list[Detection] = field(default_factory=list)
    values: set[str] = field(default_factory=set)

    def redact_text(self, text: str) -> str:
        matches = self.detector.find(text)
        if not matches:
            return text
        out, pos = [], 0
        for m in matches:
            tag = self.vault.tag(self.session, m.value)
            ph, created = self.store.get_or_create_item(
                self.session, m.kind, tag,
                lambda p, v=m.value: self.vault.encrypt_item(self.session, p, v),
            )
            self.detections.append(Detection(m.kind, ph, len(m.value), created))
            self.values.add(m.value)
            out += [text[pos : m.start], ph]
            pos = m.end
        out.append(text[pos:])
        return "".join(out)

    def redact_payload(self, body: dict) -> dict:
        return map_strings(body, self.redact_text)


def check_outbound(payload: dict, values: Iterable[str], detector: Detector) -> None:
    """Fail closed if any redacted value, or anything the detector still flags, remains.
    Error messages name the location and kind only, never the value."""
    vals = [v for v in values if v]
    for path, s in iter_strings(payload):
        for v in vals:
            if v in s:
                raise LeakBlocked(f"a detected secret survived redaction at {path}")
        left = detector.find(s, structured_only=True)
        if left:
            raise LeakBlocked(
                f"detector still flags {left[0].kind} ({left[0].end - left[0].start} chars) at {path}; "
                f"add it to the allowlist in your rules file if it is a false positive"
            )


# ------------------------------------------------------------------ rehydration
Resolver = Callable[[str], str | None]


def rehydrate_text(text: str, resolve: Resolver) -> str:
    def sub(m: re.Match) -> str:
        v = resolve(m.group(0))
        return m.group(0) if v is None else v

    return PLACEHOLDER_RE.sub(sub, text)


class StreamRehydrator:
    """Rehydrate placeholders that may be split across SSE chunks (e.g. '[EMA' + 'IL_1]')."""

    MAX_HOLD = 40

    def __init__(self, resolve: Resolver):
        self.resolve = resolve
        self.buf = ""

    def feed(self, text: str) -> str:
        self.buf += text
        self.buf = rehydrate_text(self.buf, self.resolve)
        i = self.buf.rfind("[")
        if i != -1 and "]" not in self.buf[i:] and len(self.buf) - i <= self.MAX_HOLD:
            out, self.buf = self.buf[:i], self.buf[i:]
        else:
            out, self.buf = self.buf, ""
        return out

    def flush(self) -> str:
        out, self.buf = rehydrate_text(self.buf, self.resolve), ""
        return out
