import pytest

from veil.detect import Detector

D = Detector()


@pytest.mark.parametrize("text,kind,value", [
    ("mail me at bob.smith+x@example.co.uk now", "EMAIL", "bob.smith+x@example.co.uk"),
    ("card 4111 1111 1111 1111 ok", "CARD", "4111 1111 1111 1111"),
    ("card 5500-0000-0000-0004", "CARD", "5500-0000-0000-0004"),
    ("key sk-proj-abcdefghijklmnopqrstuvwx1234", "APIKEY", "sk-proj-abcdefghijklmnopqrstuvwx1234"),
    ("aws AKIAIOSFODNN7EXAMPLE here", "AWSKEY", "AKIAIOSFODNN7EXAMPLE"),
    ("gh ghp_" + "a" * 36, "APIKEY", "ghp_" + "a" * 36),
    ("password: hunter2hunter", "SECRET", "hunter2hunter"),
    ("API_KEY=abcd1234efgh", "SECRET", "abcd1234efgh"),
    ("IBAN GB82 WEST 1234 5698 7654 32.", "IBAN", "GB82 WEST 1234 5698 7654 32"),
    ("ssn 123-45-6789", "SSN", "123-45-6789"),
    ("call 08031234567", "PHONE", "08031234567"),
    ("call +234 803 123 4567", "PHONE", "+234 803 123 4567"),
    ("call +1 (415) 555-2671", "PHONE", "+1 (415) 555-2671"),
    ("host 10.20.30.40 down", "IP", "10.20.30.40"),
    ("db postgres://admin:s3cr3tpw@db.local/x", "URLCRED", "admin:s3cr3tpw"),
    ("tok eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk", "JWT", None),
    ("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----", "PRIVATEKEY", None),
    ("blob Zm9vYmFyMTIzNDU2Nzg5MGFiY2RlZkdISUpL", "SECRET", "Zm9vYmFyMTIzNDU2Nzg5MGFiY2RlZkdISUpL"),
])
def test_detects(text, kind, value):
    ms = D.find(text)
    assert any(m.kind == kind and (value is None or m.value == value) for m in ms), ms


@pytest.mark.parametrize("text", [
    "Just a normal sentence about the weather on 2026-11-09.",
    "We shipped version 1.2.3 today and 2 bugs remain.",
    "The number 4111 1111 1111 1112 fails luhn",   # invalid card
    "IBAN-like GB00 0000 0000 0000 0000 00 invalid",
    "order id 1234567890123",                       # 13 digits, fails Luhn
    "please set the password in the vault",          # keyword without a value
    "localhost 127.0.0.1 and 0.0.0.0",
    "[EMAIL_1] wrote to [EMAIL_2]",                  # placeholders are never re-redacted
    "internationalization-and-localization-helpers",  # long but low entropy, no digits
    "agy/claude-opus-4-6-thinking",                   # model ids are not secrets
    "use claude-sonnet-4-6-medium or gemini-3-flash-preview-high",
])
def test_no_false_positive(text):
    assert D.find(text) == [], D.find(text)


def test_overlaps_resolved_by_priority():
    ms = D.find("api_key = sk-proj-abcdefghijklmnopqrstuvwx1234")
    assert [m.kind for m in ms] == ["APIKEY"]


def test_yaml_custom_rules_and_allowlist(tmp_path):
    f = tmp_path / "r.yaml"
    f.write_text("rules:\n  - {kind: PROJECT, literal: 'Project Falcon'}\n  - {kind: EMPID, regex: 'EMP-\\d{5}'}\n"
                 "allowlist:\n  values: ['noreply@example.com']\n")
    d = Detector(f)
    kinds = {m.kind for m in d.find("Project Falcon lead EMP-12345 cc noreply@example.com")}
    assert kinds == {"PROJECT", "EMPID"}
