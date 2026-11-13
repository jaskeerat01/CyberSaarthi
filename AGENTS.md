# AGENTS.md

## Repository map

- Git root and command root is `CyberSaarthi/`. CI lives in `.github/workflows/ci.yml` inside it.
- `backend/` — Django 5 + DRF + Celery (CI pins Python 3.12). Entrypoints: `config/settings.py`, `config/urls.py`, `config/celery.py`, `conftest.py`.
- `frontend/` — React 18 + TS + Vite. Entrypoints: `src/main.tsx`, `src/App.tsx`, `vite.config.ts` (Vitest config lives here too).
- `automation/` — n8n exports + synthetic fixtures. `infra/docker-compose.yml` — local stack. `load/` — k6 fast-path measurement. `docs/` — threat model, providers, n8n design, runbook.

## Commands

Backend, from `backend/` (the CI gates, in order):

```bash
pip install -e ".[dev]"
ruff check .
mypy .
python manage.py check
python manage.py spectacular --validate --file /tmp/schema.yaml
pytest --cov --cov-report=term-missing --cov-fail-under=80
bandit -r . -x "*/tests/*,*/migrations/*"
pip-audit
```

- `pytest` already adds `--cov --cov-report=term-missing -q` (pyproject `addopts`). Focused runs need `--no-cov`, e.g.
  `pytest tests/test_fastpath.py::TestFastPath::test_verified_match_resolves -q --no-cov`.

Frontend, from `frontend/` (CI order):

```bash
npm ci
npx tsc --noEmit
npm run lint
npm run format:check
npm test -- --run
npm run build
npm audit --audit-level=high
```

- `npm run build` is `tsc --noEmit && vite build`; `npm test` is `vitest run` (already single-shot).
- `npm test` excludes `e2e/`. Playwright is only for `./e2e`, starts the Vite dev server itself, and mocks the API — no backend/DB needed.

Local stack: `cp .env.example .env`, then `docker compose -f infra/docker-compose.yml up --build`.

## Environment gotchas

- `backend/.venv` may exist but be empty. Use `python3` / `python3 -m pytest` (deps are installed system-wide); verify with `python3 -c "import django"`.
- Local Python is 3.14, but `pyproject`, Ruff and mypy target 3.12 and CI pins 3.12 — keep syntax 3.12-compatible.
- `settings.py` skips the core-env fail-fast under pytest **and** for `check`, `spectacular`, `help`, `version`, `--help`. Other commands (`migrate`, `makemigrations`, `runserver`) need `DJANGO_SECRET_KEY`, `IDENTIFIER_HMAC_KEY`, `FIELD_ENCRYPTION_KEY`.
- `conftest.py` sets test env vars and calls `django.setup()` in `pytest_configure`. Do not add `DJANGO_SETTINGS_MODULE` to `pyproject.toml` or pytest-django loads settings before those env vars exist. It forces `INTERNAL_SERVICE_TOKEN=test-internal-token`; tests assert that literal.
- After model/index changes run `python manage.py makemigrations` (needs env vars), then confirm with `makemigrations --check --dry-run`.
- `backend/db.sqlite3`, `.env`, `*.sqlite3`, `dist/`, `node_modules/` are gitignored. Never commit generated DBs or `.env`.

## Configuration and secrets

- Copy `.env.example` to `.env`; never commit it or real tokens.
- `.env.example` lists vars `settings.py` does not read yet (e.g. `OPENPHISH_FEED_URL`, `GOOGLE_WEB_RISK_API_KEY`, `N8N_BASE_URL`, `N8N_API_URL`, `N8N_API_KEY`). Check `settings.py` before relying on one.
- Provider features are flag-gated and warn+disable when their key is missing.
- The n8n MCP server is configured in `../opencode.json` (enclosing dir, remote URL only). Never paste an n8n or provider API key there or into this repo. For n8n MCP work, read it, then call `get_user_preferences`, `get_instance_context`, `get_workflow_details` before mutating anything.

## Architecture guardrails

- Boundary: Celery calls n8n via `N8N_WEBHOOK_URL`; n8n never consumes Celery/Redis queues. Results return through internal callbacks.
- Internal routes (header `X-Internal-Service-Token`): `/internal/scans/{scan_id}/enrichment`, `/internal/scans/{scan_id}/complete`, `/internal/openphish/ingest`, `/internal/workflow-failures`. Changing a path or payload requires updating `automation/` and `docs/api/openapi.yaml`; CI validates the generated schema (`spectacular --validate`), not the YAML file itself.
- Safety contract (do not regress): never emit `"safe"`/`"legitimate"`; `NO_KNOWN_THREAT_DETECTED` needs the no-guarantee disclaimer; `CONFIRMED_MALICIOUS` only from `assessment/services.py:RELIABLE_PROVIDERS` (AbuseIPDB alone is technical evidence, never confirmation); show 1930 immediately when `reported_financial_loss`; never fetch user-submitted URLs server-side; defang URLs (`hxxps://…[.]…`), never render them clickable.
- Indicators: HMAC digests are versioned and scoped by `(indicator_type, digest)`; `digest` alone collides across types — query with `indicators.models.threat_indicators_for(pairs)`. Fast path requires every indicator to be `CORROBORATED`/`CONFIRMED`; any cached or fresh `NO_MATCH` falls through to the slow path.
- Promotion: `REPORTED` → `UNDER_REVIEW` after one trusted MATCH; → `CORROBORATED` after two distinct trusted MATCH providers. Never auto-`CONFIRMED`.
- `GET /api/v1/scans/{id}/report.pdf` without `?token` returns `{url, expires_in: 900}`; only the signed URL serves bytes.
- Scan endpoints are UUID-capability URLs with no authentication or ownership check — do not describe them as authenticated.

## Performance guardrails (hot paths)

- `intel/fastpath.py` batches cache misses into one `threat_indicators_for(...)` query; do not reintroduce a `SELECT` per indicator.
- `create_submission` bulk-inserts indicators, the `enrichment` callback bulk-inserts observations, and `OpenPhishEntry.ingest_urls` is bulk (one SELECT + bulk INSERT). Avoid per-row `get_or_create`/`create` on these paths.
- `ScamSubmission.content_hash`, `retention_expires_at` and `WorkflowEvent(scan, event_type)` are indexed for dedupe/purge/audit. Add new indexes on the model field (with a migration), not via ad-hoc SQL.

## Tests and traps

- Backend tests use `backend/conftest.py` for env vars and `sqlite:///db.sqlite3`.
- Never query the live OpenPhish feed per request: ingest into `intel.models.OpenPhishEntry` (12h via n8n) and match locally. `run_assessment` must consider every indicator type.
- Throttles live in `core/throttles.py`; DRF `ScopedRateThrottle` does not copy `view.throttle_scope` onto function-based views.
- Frontend Vitest hooks must return `undefined` (block body) — Vitest treats returned values as cleanup and can re-invoke mocks.
- Frontend unit tests mock `react-i18next` in `src/test/setup.ts`.
- `App.tsx` lazy-loads all routes except submission/status, wrapped in `Suspense`; keep new non-entry routes lazy. `vite.config.ts` `manualChunks` splits vendor code — keep it when changing build config.
- `defang` in `shared/api.ts` only rewrites a real scheme prefix; never blanket-replace `http`.
- Automation fixtures are synthetic only. Exported workflows are inactive and need credentials/`INTERNAL_API_BASE_URL` assigned after import. Read `docs/n8n-design.md` for the merge fan-in caveat before activating the scan workflow.

## Commit style

Conventional Commits, e.g. `feat: initialize CyberSaarthi project structure`.
