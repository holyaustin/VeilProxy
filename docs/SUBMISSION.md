# Devpost submission kit — AI pipeline secret-sharing track

**Title:** VeilProxy + ShardKey — a local secrets-redacting gateway with a Shamir-protected master key
**Tagline:** The LLM answers; your secrets never leave your machine.

## Rubric mapping
| Criterion (pts) | Evidence |
|---|---|
| Clean UI, straightforward UX (3) | Textual TUI: you-see / provider-receives / vault panes, `/unlock`, `/lock`, live detections table |
| Thorough, straightforward video (2) | `docs/DEMO_SCRIPT.md` (3 min), shows locked -> threshold unlock -> redaction -> mitmproxy proof |
| Evidence of host LLM via API (2) | Real calls through OmniRoute (OpenAI-compatible); audit log keeps upstream response id, model and token usage; screenshot OmniRoute request log |
| Optional: pre-made secret sharing (SSS) | Shamir 3-of-5 over GF(256) implemented in Rust, key-check verified |
| Low-level execution | Rust core (AES-GCM, HKDF, HMAC, Shamir, zeroize) via PyO3; Python orchestrates |

## Description (paste)
VeilProxy sits between any OpenAI-compatible client and OmniRoute. It detects API keys, cards, IBANs, emails, phones, JWTs and
private keys, encrypts each with AES-256-GCM under per-session HKDF subkeys, and sends only placeholders upstream. Replies —
including streaming, even when a placeholder is split across chunks — are rehydrated locally. The vault master key is generated
inside a Rust core, Shamir-split 3-of-5 across custodian processes, held only in zeroize-on-drop memory after threshold
approval, and wiped on lock/idle. A fail-closed outbound guard blocks any request where a secret survives. Tested with
Rust unit tests, Rust↔Python interoperability tests, a 400-prompt leak fuzz, and independent mitmproxy capture.

## Checklist before submitting
- [ ] Video uploaded to YouTube (link in submission) · [ ] repo/zip attached · [ ] screenshots: TUI, mitmweb, OmniRoute log
- [ ] State limitations honestly (hosted LLMs cannot compute on ciphertext; FHE routing is future work)
- [ ] Submit before **Nov 15, 2026, 5:00pm (+03)** = 3:00pm in Benin City
