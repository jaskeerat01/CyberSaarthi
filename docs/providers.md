# Provider Compliance Matrix

Each provider: permitted use, rate limits, redistribution restrictions, enabled flag.
Source of truth for terms; verify before enabling. TODOs link official docs — do not guess.

| Provider | Use | Rate limits | Redistribution | Enabled (MVP) |
|---|---|---|---|---|
| PhishTank | URL lookup | Per API key; quota tracked in Redis | Results may be shared per terms — TODO: https://phishtank.org/terms | ✅ True (FEATURE_PHISHTANK) |
| OpenPhish | Feed ingest every 12h into local table | Feed pull (not per-request) | Community feed; check https://openphish.com/terms | ✅ Ingest only |
| RDAP | Domain registration event date (weak signal) | IANA bootstrap authoritative server | Public RDAP data; attribution per registry | ✅ True (FEATURE_RDAP) |
| VirusTotal | Optional URL/IP lookup | Public tier: 4 req/min, 500/day, non-commercial | No redistribution of raw results — TODO: https://docs.virustotal.com/docs/about-api-tos | ❌ False (VIRUSTOTAL_ENABLED=false) |
| Google Web Risk / Safe Browsing | URL lookup | Per API key quota | Restricted by licence — enable only after deployment context matches terms. TODO: https://developers.google.com/safe-browsing/terms | ❌ False (pending licence check) |
| AbuseIPDB | IP only (check endpoint rejects domains/URLs/UPI) | Per API tier | No redistribution — TODO: https://www.abuseipdb.com/terms | ❌ False (FEATURE_ABUSEIPDB=false) |

## Adapter requirements (all providers)
- Timeout 5s default, max 2 retries exp-backoff+jitter, circuit breaker, Redis quota tracking, feature flag.
- Provider failure never fails the scan: reduces confidence, may yield INCONCLUSIVE.
- Common interface: `check_url(url)`, `check_domain(domain)`, `check_ip(ip)` → `ProviderResult{outcome, metadata, error_detail}`.
- Fixtures in `backend/intel/fixtures/` labelled captured/synthetic. CI never calls live APIs.
