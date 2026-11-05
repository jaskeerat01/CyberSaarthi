# AGENTS.md

## Repository map

The git checkout and command root is `CyberSaarthi/` (the enclosing `Cyber_Suraksha/` directory is not a repo). CI configuration lives in `.github/` inside the app repository root.

- `backend/` — Python 3.12, Django 5/DRF/Celery, pytest + pytest-django/coverage, Ruff, mypy, drf-spectacular.
- `frontend/` — React 18/TypeScript/Vite, Vitest + Playwright, ESLint, Prettier, axe-core accessibility tests.
- `automation/` — n8n workflow JSON exports + fixtures; tests use synthetic fixtures only, never live providers.
- `infra/docker-compose.yml` — PostgreSQL, Redis, backend, Celery worker, frontend, n8n.
- `load/` — k6 fast-path measurement only; latency is reported as measured, never claimed as “zero” or guaranteed.

## Commands

Backend, from `CyberSaarthi/backend/`:

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

Focused backend examples (conftest at `backend/conftest.py` supplies test env vars):

```bash
pytest tests/test_fastpath.py -q --no-cov
pytest tests/test_fastpath.py::TestFastPath::test_verified_match_resolves -q --no-cov
```

Frontend, from `CyberSaarthi/frontend/`:

```bash
npm ci
npx tsc --noEmit
npm run lint
npm run format:check
npm test -- --run
npm run build
npm audit --audit-level=high
```

Focused frontend examples (`--run` prevents Vitest watch mode):

```bash
npm test -- --run src/test/a11y.test.tsx
npm test -- --run src/features/report/ReportPage.test.tsx
```

Run `playwright test` only for the `./e2e` suite (`frontend/playwright.config.ts`). Unit tests in `src/test/` and `src/features/` use Vitest/jsdom and mock `react-i18next` via `src/test/setup.ts`.

Local stack:

```bash
cp .env.example .env
docker compose -f infra/docker-compose.yml up --build
```

## Configuration and secrets

- Copy `CyberSaarthi/.env.example` to `CyberSaarthi/.env`; never commit `.env` or real tokens.
- Backend core variables are `DJANGO_SECRET_KEY`, `IDENTIFIER_HMAC_KEY`, and `FIELD_ENCRYPTION_KEY`. `settings.py` skips the fail-fast guard when `pytest` is already loaded, so test runs behave differently from runtime commands.
- Provider features are flag-gated and warn+disable when their keys are missing.
- The n8n remote MCP config lives in `../opencode.json` (enclosing dir) and already points at `enrichment`; do not paste an n8n API key into this repo or that file.

## Architecture guardrails

- Keep the webhook boundary: Celery invokes n8n via `N8N_WEBHOOK_URL`; n8n never consumes Celery/Redis queues. For n8n MCP work read `../opencode.json` first, then call `get_user_preferences`, `get_instance_context`, and `get_workflow_details` before mutating anything.
- Current backend internal routes are `/internal/scans/{scan_id}/enrichment`, `/internal/scans/{scan_id}/complete`, `/internal/openphish/ingest`, and `/internal/workflow-failures` (n8n Error Trigger handler). The OpenPhish sync workflow targets `/internal/openphish/ingest`.
- Never change an internal path or payload without updating `automation/` exports and `docs/api/openapi.yaml`; CI validates the generated OpenAPI schema.
- Never output `"safe"` or `"legitimate"`. `NO_KNOWN_THREAT_DETECTED` needs the no-guarantee disclaimer. `CONFIRMED_MALICIOUS` is only for reliable/verified sources in `assessment/services.py:RELIABLE_PROVIDERS`; AbuseIPDB alone is technical evidence, never confirmation.
- When `reported_financial_loss` is true, surface the 1930 helpline immediately. The system never declares confirmed fraud.
- Never fetch user-submitted URLs server-side and never render raw URLs as clickable links; use defanged display (`hxxps://…[.]…`) for extracted indicators.
- HMAC digests are versioned and scoped by `(indicator_type, digest)`. Fast path requires every extracted indicator to be `CORROBORATED` or `CONFIRMED`; any fresh or cached `NO_MATCH` must fall through to the slow path.
- Promotion: `REPORTED` → `UNDER_REVIEW` after one trusted provider MATCH; → `CORROBORATED` after two distinct trusted MATCH providers. Never promote to `CONFIRMED` automatically.
- `GET /api/v1/scans/{scan_id}/report.pdf` without a token returns `{url, expires_in: 900}`; only the returned signed URL serves the PDF.

## Tests and traps

- Backend tests use `backend/conftest.py` for env vars and `DATABASE_URL` from `sqlite:///db.sqlite3`.
- Keep Vitest hooks returning `undefined` (block body). Vitest invokes hook return values as cleanup callbacks, so an expression body returning a mock stub can accidentally invoke the implementation post-test.
- Never query the live OpenPhish feed per request; ingest into `intel.models.OpenPhishEntry` (every 12h via n8n) and match locally. In `run_assessment`, every extracted indicator type must be considered.
- For throttle changes, use `core/throttles.py`; DRF `ScopedRateThrottle` relies on `view.throttle_scope`, which is not copied for function-based views.
- For new settings or dependencies, run the relevant checker before touching CI: backend needs `ruff check .`, `mypy .`, `python manage.py check`; frontend needs `tsc --noEmit`, `lint`, `format:check`.

## Commit style

Use Conventional Commits, e.g. `feat: initialize CyberSaarthi project structure`.
