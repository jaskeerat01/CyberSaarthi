# ADR 0002: Celery owns state; n8n is invoked via webhook

## Status
Accepted

## Context
Slow-path enrichment needs retries, timeouts, and audit. n8n workflows run in their own engine and cannot reliably own Celery job state.

## Decision
- Celery creates the investigation job, invokes n8n via authenticated webhook (`POST /webhook/cybersathi/scan-investigation`), and owns retries/timeouts/DLQ.
- n8n returns results via `POST /internal/scans/{id}/enrichment` and `/complete` (service-token auth, no public route).
- n8n never consumes Celery/Redis queues directly.
- n8n performs external lookups only; it never fetches user-submitted URLs.

## Consequences
- Every pipeline stage writes `workflow_events`.
- n8n workflow timeout 60s; Celery task timeout bounds the whole job.
- Error Trigger in n8n posts ERROR enrichment so Celery can retry.
