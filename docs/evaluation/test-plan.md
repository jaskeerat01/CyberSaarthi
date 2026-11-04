# Test Plan

## Unit (pytest, Vitest)
- Normalisation: NFKC, zero-width strip, URL parsing, IDNA/punycode, default-port removal, trailing-dot strip, embedded-credential rejection, 5000-char limit, language detect.
- Extraction: URL/DOMAIN/IP/PHONE/UPI/EMAIL patterns (en + hi).
- Rule evaluation + classification order (first match wins).
- Indicator state transitions (only trusted/human promotion beyond REPORTED).
- HMAC digest determinism + key rotation.

## Integration
- PostgreSQL + Redis via Docker Compose/Testcontainers.
- Concurrency: parallel upserts of same indicator → single row, no IntegrityError leak.
- n8n workflow tested via MCP `test_workflow` with pin data from `automation/fixtures/` (no live provider calls).

## Contract
- Responses validated against OpenAPI (`docs/api/openapi.yaml`); frontend Zod schemas generated/checked against same contract.

## Providers
- All adapters tested against labelled fixtures (captured/synthetic). CI never hits live APIs. Live tests behind `pytest -m live` marker + manual trigger only.

## Performance
- Fast-path load test (k6/Locust): report P50/P95. Target measured, never "zero latency".

## Evaluation harness
- Labelled phishing/benign dataset with separate tuning + held-out sets. Never tune on held-out.
- Metrics: precision, recall, false-positive rate, entity extraction accuracy, workflow success rate, retry outcomes, cache hit ratio, provider-outage behaviour, PDF success rate.
- Document dataset sources/licences in `datasets/README.md`.

## Coverage gates
- Backend domain + risk-engine ≥80%; frontend ≥70%. Enforced in CI.

## Frontend / E2E
- Component tests per page state (loading/success/error/empty).
- Playwright submission→report flow with mocked API.
- axe accessibility checks (WCAG 2.2 AA).
