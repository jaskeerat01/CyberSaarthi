# Runbook

## Health
- `GET /healthz` — liveness. `GET /readyz` — DB + Redis connectivity.
- Prometheus: request latency, per-stage duration, provider outcomes, circuit-breaker state, remaining quota.

## Common failures

| Symptom | Likely cause | Action |
|---|---|---|
| Scans stuck PENDING | Celery worker down | Restart worker; inspect DLQ |
| n8n webhook 401 | Token mismatch | Verify `N8N_WEBHOOK_TOKEN` matches "CyberSathi Service Token" credential |
| Provider ERROR spike | Outage / quota | Check circuit-breaker + Redis quota keys; scans degrade to INCONCLUSIVE/LOW confidence |
| PDF generation fails | WeasyPrint native deps | Check container logs; fonts/Pango installed in image |
| Workflow timeout | Slow provider | Celery retries (max 2, exp backoff); check 60s n8n timeout setting |

## Pause n8n workflow
Via MCP: `unpublish_workflow` (stops production execution). Re-publish with `publish_workflow` after fix. Celery keeps jobs queued.

## Dead-letter queue
Failed Celery tasks → DLQ. Inspect, fix root cause, requeue via task replay.

## Key rotation
HMAC rotation per ADR 0003: set new `IDENTIFIER_HMAC_KEY` + `IDENTIFIER_HMAC_KEY_ID`, dual-write, re-hash, retire.
