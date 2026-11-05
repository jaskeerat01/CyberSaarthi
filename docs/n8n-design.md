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
4. URL/DOMAIN branch (parallel): PhishTank HTTP (credential "PhishTank API Key") + RDAP HTTP (via the public `rdap.org` proxy, which resolves the authoritative RDAP server from the IANA bootstrap itself)
   - NOTE: `docs/providers.md` describes IANA bootstrap; the shipped workflow uses `rdap.org` as a pragmatic proxy. The Python `RdapProvider` resolves the IANA bootstrap directly. Either way the registration date is the only signal used (weak, never confirms).
5. IP branch: AbuseIPDB HTTP **GET** (credential "AbuseIPDB API Key", gated by FEATURE_ABUSEIPDB); MATCH requires `abuseConfidenceScore >= 50` (reputation only — never confirms)
6. PHONE/UPI/EMAIL: passthrough UNSUPPORTED (no external lookup in MVP)
7. Normalise outputs: `{type, normalised_value, provider, outcome, response_reference, error_detail}`, outcome ∈ MATCH/NO_MATCH/ERROR/RATE_LIMITED/UNSUPPORTED
   - PhishTank MATCH requires `results.verified && results.valid` (unverified community submissions never confirm)
   - User-Agent: `CyberSathi/1.0`
8. Per-branch error handling: 5s timeout, continueOnFail → ERROR
9. Merge keyed by scan_id
10. Send enrichment (credential "CyberSathi Internal Service Token")
11. Send complete
12. Error Trigger → `POST /internal/workflow-failures` with workflow name, execution id, failed node and message (the API logs metadata only)

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

## Pre-activation verification (mandatory before publishing)
- **Merge fan-in semantics:** `Collect Observations` merges 4 branch outputs.
  n8n's Merge node behavior around incomplete branches must be verified with a
  URL-only payload in the actual n8n instance. If the Merge node only fires
  when ALL inputs have data, URL-only scans will hang (no enrichment/complete
  callbacks → scan stuck RUNNING). Remedy: add `settings: {alwaysOutputData: true}`
  to each branch-end node so every branch always emits, and filter empty items
  in `Build Enrichment Payload`. Do not activate the workflow until a URL-only
  payload is observed producing both callbacks.
- Assign credentials after import (header auth for the webhook, generic
  credential for PhishTank/AbuseIPDB/internal API calls, `INTERNAL_API_BASE_URL`
  env) and activate the workflow; exports are inactive by default.
