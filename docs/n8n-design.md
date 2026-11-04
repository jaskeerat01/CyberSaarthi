# n8n Workflow Design — CyberSathi - Scan Investigation

## Contract

**Trigger:** Webhook `POST /webhook/cybersathi/scan-investigation`
- Auth: header auth, credential "CyberSathi Service Token" (name/ID only, never values in repo).
- Payload: `{ scan_id, indicators: [{type, normalised_value}], attempt }`
- Malformed → 400, no downstream calls.

**Callbacks (internal, service-token auth):**
- `POST {{INTERNAL_API_BASE_URL}}/internal/scans/{scan_id}/enrichment` — observations list
- `POST {{INTERNAL_API_BASE_URL}}/internal/scans/{scan_id}/complete` — `{status: "enrichment_done"}`

## Nodes (in order)
1. Webhook trigger (header auth)
2. Validate payload (Code node) — required fields or 400
3. Switch by indicator type: URL, DOMAIN, IP, PHONE, UPI, EMAIL
4. URL/DOMAIN branch (parallel): PhishTank HTTP (credential "PhishTank API Key") + RDAP HTTP (IANA bootstrap → authoritative server)
5. IP branch: AbuseIPDB HTTP (credential "AbuseIPDB API Key", gated by FEATURE_ABUSEIPDB)
6. PHONE/UPI/EMAIL: passthrough UNSUPPORTED (no external lookup in MVP)
7. Normalise outputs: `{provider, outcome, response_reference, error_detail}`, outcome ∈ MATCH/NO_MATCH/ERROR/RATE_LIMITED/UNSUPPORTED
8. Per-branch error handling: 5s timeout, continueOnFail → ERROR
9. Merge keyed by scan_id
10. Send enrichment (credential "CyberSathi Internal Service Token")
11. Send complete
12. Error Trigger → POST enrichment ERROR for affected scan_id (Celery retry path)

## Config
- Tags: `cybersathi`, `mvp`. Sticky notes per section.
- Env vars: `INTERNAL_API_BASE_URL`, `FEATURE_PHISHTANK`, `FEATURE_RDAP`, `FEATURE_ABUSEIPDB`. No hardcoded hosts.
- Workflow timeout: 60s.
- n8n never fetches user-submitted URLs; never consumes Celery/Redis queues.

## Tests (fixtures in automation/fixtures/, no live calls in CI)
1. all providers succeed
2. one provider timeout → ERROR, workflow continues
3. 429 → RATE_LIMITED
4. all providers fail → completes for Celery retry
5. malformed payload → 400
6. missing service token → 401/403
