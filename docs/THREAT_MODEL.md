# Threat model

**Protects against:** the LLM provider / OmniRoute upstream logging or training on your secrets and identifiers;
provider-side data breaches; a stolen `vault.db` (ciphertext + keyed tags only); a single compromised custodian
(needs k of n); the gateway being left unlocked (idle auto-lock); accidental leaks due to a redaction bug
(fail-closed guard, fuzz-tested over 400 generated prompts).

**Does not protect against**
- Anything the detector misses (free-form sensitive prose, unusual formats). Use custom rules; treat detection as defence-in-depth, not a guarantee.
- Metadata leakage: placeholder *kinds* and counts, prompt length, timing, and the surrounding text.
- A compromised local machine while the vault is unlocked (malware can call the gateway or read process memory).
- Shard transport: custodians release shards over localhost HTTP with a bearer token. For multi-machine use, put it behind TLS/SSH tunnels.
- Prompt injection that makes the model emit placeholders: they are only rehydrated for *you* locally, but agents that forward replies elsewhere should be reviewed.
- The OmniRoute API key itself must reach OmniRoute, and OmniRoute holds provider keys.
- Python string memory cannot be zeroized: decrypted values handled by the gateway briefly exist in Python heap memory (the master key does not).
- Side channels of the AES-GCM/GF(256) code are mitigated (RustCrypto, branch-free GF multiply) but not formally audited.

Not a replacement for an audit; this is a hackathon-grade system with production-minded design.
