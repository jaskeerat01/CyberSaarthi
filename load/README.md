# Load tests

## k6 fast-path test (`k6-fastpath.js`)

Measures **P50/P95** for scan submission when indicators are already verified
(fast path — cache/DB hit, no n8n round-trip). Latency is *measured* and
reported; it is never asserted as "zero latency" (docs/evaluation/test-plan.md).

### Prerequisites

1. Stack running (backend + Redis + DB): `docker compose -f infra/docker-compose.yml up`
   or local `manage.py runserver`.
2. Seed a verified indicator the script will submit, or the requests fall
   through to the slow path:

```bash
cd backend
export DJANGO_SECRET_KEY=... IDENTIFIER_HMAC_KEY=... FIELD_ENCRYPTION_KEY=... INTERNAL_SERVICE_TOKEN=...
python manage.py shell -c "
from core.crypto import hmac_digest
from indicators.models import upsert_indicator
d, _ = hmac_digest('https://seeded-bad.example/login')
i, _ = upsert_indicator('URL', d); i.status = 'CONFIRMED'; i.save(update_fields=['status'])
d2, _ = hmac_digest('seeded-bad.example')
i2, _ = upsert_indicator('DOMAIN', d2); i2.status = 'CONFIRMED'; i2.save(update_fields=['status'])
print('seeded')
"
```

> Seed **every** indicator type the submission will extract (URL + DOMAIN), or
> `fast_path_check` correctly falls through to the slow path for the unverified one.

### Run

```bash
k6 run load/k6-fastpath.js \
  -e BASE_URL=http://localhost:8000 \
  -e SEED_URL=https://seeded-bad.example/login \
  -e RATE=20 -e DURATION=1m
```

- `fast_path` scenario: unique text per request (bypasses content-hash dedupe)
  with the same seeded indicator (serves from fast-path cache).
- `baseline` scenario: no indicators — structural rules only, for comparison.
- Output includes `p(50)` / `p(95)` of `http_req_duration` plus the custom
  `handleSummary` JSON block.
- Thresholds gate only **availability** (`http_req_failed < 1%`, `checks > 95%`);
  latency numbers are reported, not gated — record them in
  `docs/evaluation/report.md` after a run.

### CI note

Not wired into CI (needs a running stack + seeded data). Run manually before
releases and paste results into the evaluation report.
