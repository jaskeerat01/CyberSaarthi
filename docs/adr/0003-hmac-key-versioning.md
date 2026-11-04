# ADR 0003: Keyed HMAC digests with key versioning

## Status
Accepted

## Context
Identifiers (URLs, phones, UPI) must be matchable without storing plaintext beyond retention. Plain SHA-256 is brute-forceable for low-entropy values (phone numbers).

## Decision
- Digests = HMAC-SHA256 with a 32-byte key, base64 in env (`IDENTIFIER_HMAC_KEY`).
- Key version stored alongside each digest (`IDENTIFIER_HMAC_KEY_ID` / per-row `key_version`).
- Rotation: dual-write during transition, re-hash on read, retire old keys after window.
- Raw values encrypted at rest (Fernet `FIELD_ENCRYPTION_KEY`), retention default 30 days, user-deletable.

## Consequences
- `threat_indicators` constraint: `UNIQUE(indicator_type, digest)`; no standalone index on digest alone.
- Migration script needed for key rotation.
