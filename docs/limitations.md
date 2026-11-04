# Documented Limitations (MVP)

- No zero-day detection claim. NO_KNOWN_THREAT_DETECTED is not a safety guarantee.
- The system never determines confirmed financial fraud — only a human/official process does.
- No automatic browsing/rendering of submitted URLs; no APK execution; no UPI/payment verification.
- No automatic complaint filing on a user's behalf.
- Exact provider rate limits/terms must be verified against official docs before production enablement (see `docs/providers.md` TODOs).
- Hindi translations require native-speaker review before public release.
- Optional LLM extraction is Phase 2 — not in MVP. Rules-only classification.
- Telegram bot is Phase 2 (webhook stub implemented, not separately deployed).
