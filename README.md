# VeilProxy + ShardKey

A **local, secrets-redacting gateway** for OpenAI-compatible LLM APIs (built for **OmniRoute**),
with a **Shamir-protected master key**. Hackathon track: *AI pipeline secret sharing*.

```
 you / any OpenAI client ──► VeilProxy (127.0.0.1:8787) ──► OmniRoute (:20128/v1) ──► any provider model
                               │  detect → encrypt (AES-256-GCM) → send placeholders only
                               │  receive reply → rehydrate placeholders locally
                               └─ ShardKey vault: master key = Shamir 3-of-5, exists only in Rust memory
```

The provider sees `Email [EMAIL_1] about card [CARD_1] using key [APIKEY_1]`.
You see the real values. The master key is never on disk and never in Python memory.

## What is inside
| Layer | Tech | What it does |
|---|---|---|
| Crypto core | **Rust** (PyO3/maturin): `aes-gcm`, `hkdf`, `hmac`, `zeroize`, own GF(256) Shamir | AES-256-GCM per-secret encryption, per-session HKDF subkeys, Shamir split/combine, zeroized key custody |
| Detection | Python: regex + Luhn/IBAN/SSN validators + entropy + optional Presidio/spaCy + YAML rules | Finds API keys, JWTs, private keys, cards, IBAN, emails, phones (incl. Nigerian), IPs, URL credentials, passwords |
| Gateway | FastAPI + httpx | OpenAI-compatible `/v1/chat/completions` (+ streaming) and `/v1/models`, forwards to **OmniRoute** |
| Vault | SQLite (ciphertext only) + custodian processes | 3-of-5 threshold approval to unlock; idle auto-lock; `423 Locked` when sealed |
| Safety net | Outbound guard | Fail-closed: if any detected secret survives redaction the request is blocked (HTTP 422) |
| UI | **Textual** TUI | 3 panes: *what you see* / *what the provider receives* / *vault + detections* |
| Evidence | mitmproxy (reverse mode) + audit log | Independent proof of exactly what left the machine |

A pure-Python crypto fallback with identical wire formats is used automatically if the Rust core isn't built.

## Quick start (details: `docs/INSTALL.md`)
```bash
make install                      # venv + deps + builds the Rust core
cp .env.example .env              # set OMNIROUTE_API_KEY and VEIL_DEFAULT_MODEL
veil init                         # 3-of-5 shards
veil custodians --approve 1,2,3   # terminal A (demo custodians)
veil serve                        # terminal B
veil tui                          # terminal C  ->  /unlock, then chat
veil doctor                       # checks everything
```
No OmniRoute yet? `veil mock-omniroute` starts an echo server on :20128 (clearly a mock, not an LLM).

## Use it from any OpenAI client
Point the client at `http://127.0.0.1:8787/v1` (any key, or `VEIL_CLIENT_KEY`). Optional header
`X-Veil-Session: <name>` keeps placeholder numbering stable per conversation.

## Tests
`make rust-test` (7 Rust tests) · `make test` (60 Python tests incl. a 400-prompt leak fuzz, a Rust↔Python
interoperability test, streaming-split property tests, a headless TUI run) · `veil selftest`.

## Honest limits (read `docs/THREAT_MODEL.md`)
A hosted LLM must read the text it answers, so this cannot be end-to-end encryption. VeilProxy keeps
*secrets and identifiers* away from the provider; anything the detector misses is sent in clear, and
placeholders reveal the *type* of data. The OmniRoute API key necessarily reaches OmniRoute. The protected
"master key" is the vault key that guards your secrets.
