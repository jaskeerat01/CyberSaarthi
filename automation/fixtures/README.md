# Automation fixtures

Labelled test fixtures for the n8n investigation workflow. **Never call live providers in CI.**

- `phishtank_match.json` — synthetic captured response (MATCH)
- `phishtank_no_match.json` — synthetic (NO_MATCH)
- `rdap_new_domain.json` — synthetic RDAP with recent registration date
- `abuseipdb_match.json` — synthetic AbuseIPDB high score
- `payload_valid.json` — well-formed webhook payload
- `payload_malformed.json` — missing required fields (expect 400)

Each file is labelled `captured` or `synthetic` in its `_fixture_meta` field.
