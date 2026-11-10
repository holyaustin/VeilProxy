# 3-minute demo video script (record the terminal; mitmweb in a browser beside it)
1. **(0:00)** "A hosted LLM must read your prompt — so VeilProxy makes sure it never reads your secrets." Show the 3-pane TUI.
2. **(0:15)** Prompt with the vault locked -> red "Vault is locked". "Nothing left the machine."
3. **(0:30)** `/shards <2 shards>` -> refused (insufficient). Then `/unlock`: custodians 1-3 approve, 4-5 deny -> unlocked (3-of-5).
4. **(1:00)** Type: *Draft an email to ada.obi@example.com, card 4111 1111 1111 1111, deploy key sk-proj-Q8x2…* .
   Pane ① shows real values streaming in; pane ② shows `[EMAIL_1] [CARD_1] [APIKEY_1]`; table lists detections.
5. **(1:45)** Switch to mitmweb: open the POST to OmniRoute — placeholders only. Show the OmniRoute dashboard request log / response id (proof of real host LLM via API).
6. **(2:15)** Ask a follow-up using "that email" — placeholder reuse keeps context. `/lock`; next prompt fails: key wiped from memory.
7. **(2:40)** Terminal: `cargo test`, `pytest`, `veil selftest` -> "leaked to provider: 0". Close with limits (see THREAT_MODEL).
