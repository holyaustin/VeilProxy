# Architecture

## Request path
1. Client -> `POST /v1/chat/completions` (OpenAI schema) on VeilProxy.
2. `ensure_unlocked()` — sealed vault => HTTP 423; nothing is forwarded.
3. Every string leaf of the JSON body (except structural keys like `role`, `model`) is scanned by the Detector.
4. Each match: `tag = HMAC(session_tag_key, value)` -> existing placeholder (dedup) or new `[KIND_n]`;
   value encrypted with AES-256-GCM under a per-session HKDF subkey, AAD = `session|placeholder`; ciphertext stored.
5. **Outbound guard** (fail-closed): exact-substring check for every redacted value + re-scan of the final payload.
6. Optional policy: if a high-sensitivity kind was found and `VEIL_LOCAL_MODEL` is set, model is switched to the local one.
7. Forward to OmniRoute with its own API key. Reply (JSON or SSE) is rehydrated: placeholders are looked up and
   decrypted lazily; the SSE rehydrator buffers partial `[EMA` + `IL_1]` fragments so they never reach the client.
8. Audit row stores the redacted outbound payload, detections (kind/placeholder/length only), upstream id/model/usage.

## Key custody (ShardKey)
`veil init` calls the Rust core, which draws 32 random bytes, Shamir-splits them (GF(2^8), 3-of-5), returns the
shares + a 128-bit HKDF key-check, and wipes the key. Unlock = collect >=3 shares from custodians (or paste them),
Rust reconstructs, verifies the key-check in constant time, keeps the key in `Zeroizing` memory, and the shares are dropped.
`lock`, idle timeout, or process exit wipes it. Python only calls `encrypt/decrypt/tag`.

## Module map
`core/src/core.rs` crypto · `core/src/lib.rs` PyO3 · `veil/crypto/pure.py` fallback · `veil/detect/` detection ·
`veil/vault/` store, manager, custodian · `veil/gateway/` app + redaction · `veil/tui/` UI · `veil/cli.py` commands.
