# Threat Model (STRIDE)

Baseline: OWASP ASVS Level 2, OWASP Top 10. Completed before feature work per spec §14.

## Assets
- Raw submissions (encrypted PII: phone, UPI, URLs, screenshots)
- HMAC digests + threat indicator table
- Scan assessments + PDFs
- Service tokens, provider API keys, Fernet/HMAC keys

## Trust boundaries
1. Public web / Telegram → DRF gateway
2. DRF gateway → Celery (internal)
3. Celery → n8n webhook (authenticated)
4. n8n → internal API endpoints (service-token, network-restricted)
5. Providers (external TI) → Django adapters (never trust provider payloads blindly)

## STRIDE analysis

### Spoofing
- Attacker submits fake reports to pollute threat intel.
  - Mitigation: single user report only reaches REPORTED; promotion needs trusted-source corroboration or human review.
- Attacker impersonates n8n callbacks.
  - Mitigation: separate service tokens for n8n webhook vs internal API; network-level restriction; constant-time compare.

### Tampering
- Attacker modifies assessment/PDF.
  - Mitigation: ruleset version + rule IDs immutable per assessment; PDFs generated on demand from stored evidence; signed URLs short-lived.
- LLM prompt injection (Phase 2).
  - Mitigation: submitted content is untrusted; strict Pydantic schema validation; discard on failure; LLM provides signals only, never classification.

### Repudiation
- Dispute over scan history.
  - Mitigation: `workflow_events` audit per scan (event_type, attempt, payload_summary — redacted).

### Information disclosure
- Raw content leakage via logs/exports.
  - Mitigation: never log phone/UPI/full URL query/raw content — log `scan_id`. Secrets only via env/secret manager; gitleaks in CI. No secrets in frontend bundle (only `VITE_API_BASE_URL`). CSP, no inline scripts, no `dangerouslySetInnerHTML`, defanged URLs in UI.
- Indicator enumeration.
  - Mitigation: HMAC digests (not plain SHA-256); rate limiting; no bulk export endpoint.

### Denial of service
- Submission flood, expensive PDF generation.
  - Mitigation: DRF throttling per IP + per token (stricter for submissions/reports); input size limit 5,000 chars default; PDF needs auth + short-lived signed URL.

### Elevation of privilege
- SSRF via user URLs (MVP never fetches URLs → surface removed; future fetching requires egress allowlist).
- IDOR on scan endpoints.
  - Mitigation: scan access scoped to submitter; signed URLs for PDFs; internal endpoints not publicly routed.

## Data lifecycle
- Retention default 30 days for raw content (configurable). User deletion via `DELETE /api/v1/scans/{id}`. Submissions never sold/shared.
- Screenshots: EXIF stripped before PDF inclusion.

## Residual risks
- Provider data accuracy is not guaranteed; confidence reflects reliability.
- Hindi translations require native-speaker review before release.
