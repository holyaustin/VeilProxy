"""Secret / PII detection: regex rules + checksum validators + entropy + optional NLP + YAML rules."""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

PLACEHOLDER_RE = re.compile(r"\[[A-Z][A-Z0-9]*_\d+\]")


@dataclass(frozen=True)
class Match:
    start: int
    end: int
    kind: str
    value: str
    priority: int = 0
    source: str = "regex"


# ------------------------------------------------------------------ validators
def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _card_ok(v: str) -> bool:
    d = re.sub(r"[ -]", "", v)
    return d.isdigit() and 13 <= len(d) <= 19 and luhn_ok(d) and len(set(d)) > 1


def _iban_ok(v: str) -> bool:
    s = v.replace(" ", "").upper()
    if not (15 <= len(s) <= 34) or not s[:2].isalpha() or not s[2:4].isdigit():
        return False
    r = s[4:] + s[:4]
    return int("".join(str(int(c, 36)) for c in r)) % 97 == 1


def _ssn_ok(v: str) -> bool:
    a, g, s = v.split("-")
    return a not in ("000", "666") and not a.startswith("9") and g != "00" and s != "0000"


def _phone_ok(v: str) -> bool:
    digits = re.sub(r"\D", "", v)
    return 10 <= len(digits) <= 15 and (v.lstrip().startswith("+") or re.search(r"[\s.()-]", v) is not None)


def _ip_ok(v: str) -> bool:
    return v not in ("0.0.0.0", "127.0.0.1", "255.255.255.255")


def _not_placeholder(v: str) -> bool:
    return not PLACEHOLDER_RE.fullmatch(v) and not (v.startswith("[") and v.endswith("]"))


def _inside_digit_run(text: str, s: int, e: int) -> bool:
    before = s >= 2 and text[s - 1] in " .-" and text[s - 2].isdigit()
    after = e + 1 < len(text) and text[e] in " .-" and text[e + 1].isdigit()
    return before or after


def shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((s.count(c) / n) * math.log2(s.count(c) / n) for c in set(s))


# ------------------------------------------------------------------ rules
@dataclass
class Rule:
    kind: str
    pattern: re.Pattern
    priority: int
    group: int = 0
    validate: Callable[[str], bool] | None = None


def _r(kind: str, rx: str, prio: int, group: int = 0, validate=None, flags: int = 0) -> Rule:
    return Rule(kind, re.compile(rx, flags), prio, group, validate)


BUILTIN_RULES: list[Rule] = [
    _r("PRIVATEKEY", r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z ]+ )?PRIVATE KEY-----", 100),
    _r("JWT", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", 90),
    _r("URLCRED", r"(?<=://)[^\s/:@]+:[^\s/@]+(?=@)", 85),
    _r("AWSKEY", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", 80),
    _r("APIKEY", r"\bsk-(?:proj-|ant-|or-v1-|svcacct-)?[A-Za-z0-9_-]{20,}", 80),
    _r("APIKEY", r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b", 80),
    _r("APIKEY", r"\bAIza[0-9A-Za-z_-]{35}\b", 80),
    _r("APIKEY", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b", 80),
    _r("APIKEY", r"\bxox[abprs]-[A-Za-z0-9-]{10,}", 80),
    _r("APIKEY", r"\bhf_[A-Za-z0-9]{30,}\b", 80),
    _r(
        "SECRET",
        r"\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|token)\b[\"']?\s*[:=]\s*[\"']?([^\s\"',;]{6,})",
        70, group=1, validate=_not_placeholder, flags=re.IGNORECASE,
    ),
    _r("CARD", r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])", 60, validate=_card_ok),
    _r("IBAN", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b", 60, validate=_iban_ok),
    _r("SSN", r"\b\d{3}-\d{2}-\d{4}\b", 60, validate=_ssn_ok),
    _r("EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", 55),
    _r("PHONE", r"(?<![\w.])(?:\+234|234|0)[789][01]\d{8}(?![\w])", 52),  # Nigerian mobile
    _r("PHONE", r"(?<![\w.])\+?\d{1,3}[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}(?![\w])", 50, validate=_phone_ok),
    _r("IP", r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", 40, validate=_ip_ok),
]

_ENTROPY_RE = re.compile(r"(?<![\w+/=-])[A-Za-z0-9+/_=-]{24,}(?![\w+/=-])")


class Detector:
    def __init__(
        self,
        rules_file: Path | str | None = None,
        entropy: bool = True,
        nlp: bool = False,
        entropy_threshold: float = 3.9,
    ):
        self.rules: list[Rule] = list(BUILTIN_RULES)
        self.allow_values: set[str] = set()
        self.allow_regex: list[re.Pattern] = []
        self.entropy = entropy
        self.entropy_threshold = entropy_threshold
        self._nlp = None
        if rules_file and Path(rules_file).exists():
            self._load_rules(Path(rules_file))
        if nlp:
            from .nlp import PresidioNER  # lazy: heavy optional dependency

            self._nlp = PresidioNER()

    def _load_rules(self, path: Path) -> None:
        import yaml

        data = yaml.safe_load(path.read_text()) or {}
        for r in data.get("rules", []):
            kind = str(r.get("kind", "CUSTOM")).upper()
            if "regex" in r:
                rx = re.compile(r["regex"])
            elif "literal" in r:
                rx = re.compile(re.escape(str(r["literal"])))
            else:
                continue
            self.rules.append(Rule(kind, rx, int(r.get("priority", 95)), int(r.get("group", 0))))
        al = data.get("allowlist", {}) or {}
        self.allow_values |= set(map(str, al.get("values", [])))
        self.allow_regex += [re.compile(x) for x in al.get("regex", [])]

    def _allowed(self, v: str) -> bool:
        return v in self.allow_values or any(r.fullmatch(v) for r in self.allow_regex)

    def _candidates(self, text: str) -> Iterable[Match]:
        for rule in self.rules:
            for m in rule.pattern.finditer(text):
                s, e = m.span(rule.group)
                if s < 0:
                    continue
                v = text[s:e]
                if rule.validate and not rule.validate(v):
                    continue
                if self._allowed(v) or PLACEHOLDER_RE.fullmatch(v):
                    continue
                if rule.kind == "PHONE" and _inside_digit_run(text, s, e):
                    continue  # a slice of a longer number (e.g. a card that failed Luhn), not a phone
                yield Match(s, e, rule.kind, v, rule.priority)
        if self.entropy:
            for m in _ENTROPY_RE.finditer(text):
                v = m.group(0)
                if self._allowed(v):
                    continue
                has_l, has_u, has_d = (bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"\d"))
                # random-looking mixed-case alphanumerics (base64/random tokens) ...
                mixed = has_l and has_u and has_d and shannon(v) >= self.entropy_threshold
                # ... or long hex strings (keys, hashes). Plain kebab-case words / model ids are NOT flagged.
                hexkey = len(v) >= 32 and re.fullmatch(r"[0-9a-fA-F]+", v) is not None and shannon(v) >= 3.0
                if mixed or hexkey:
                    yield Match(m.start(), m.end(), "SECRET", v, 20, "entropy")

    def find(self, text: str, structured_only: bool = False) -> list[Match]:
        """Non-overlapping matches, highest priority (then longest) wins, sorted by position."""
        if not text:
            return []
        cands = list(self._candidates(text))
        if self._nlp is not None and not structured_only:
            cands += [c for c in self._nlp.find(text) if not self._allowed(c.value)]
        cands.sort(key=lambda m: (-m.priority, -(m.end - m.start), m.start))
        chosen: list[Match] = []
        for c in cands:
            if all(c.end <= k.start or c.start >= k.end for k in chosen):
                chosen.append(c)
        chosen.sort(key=lambda m: m.start)
        return chosen
