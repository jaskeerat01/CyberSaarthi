# Citizen CyberSathi

Citizen-focused cyber scam intelligence and phishing early-warning platform.
Submits suspicious text/URLs → explainable assessment in English and Hindi + downloadable evidence/complaint-preparation report.

## Safety contract

- Never outputs "safe"/"legitimate". `NO_KNOWN_THREAT_DETECTED` is not a guarantee of safety.
- Never fetches user-submitted URLs server-side (MVP). No SSRF surface.
- System never determines confirmed financial fraud — only a human/official process does.
- If a user reports financial loss, the National Cyber Crime Helpline **1930** is shown prominently and immediately.

See `docs/threat-model.md`, `docs/providers.md`, `docs/adr/`.

## Layout

- `backend/` — Django REST gateway (Python 3.12, Django 5.x, DRF, Celery, Redis, PostgreSQL 16)
- `frontend/` — React 18 + TypeScript + Vite, Tailwind, TanStack Query, react-i18next, Zod
- `automation/` — n8n workflow exports + fixtures + README
- `docs/` — adr, api, threat-model, providers, evaluation, runbook, accessibility
- `infra/` — Docker Compose
- `datasets/` — scripts/metadata only (no raw sensitive data)

## Local dev

```bash
cp .env.example .env   # fill placeholders — never commit .env
docker compose -f infra/docker-compose.yml up --build
# backend http://localhost:8000/healthz
# frontend http://localhost:5173
# n8n http://localhost:5678 (self-hosted)
```

See `docs/runbook.md` for operations.
