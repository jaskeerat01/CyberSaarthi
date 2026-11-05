# Evaluation Report (MVP)

Status: pending dataset. Metrics to report once a labelled dataset is available (see `datasets/sources.md`):

- Precision, recall, false-positive rate
- Entity extraction accuracy
- Workflow success rate, retry outcomes
- Cache hit ratio, provider-outage behaviour
- PDF generation success rate

Backend unit/API tests: 108 passing (normalisation, classification, indicators, providers, API, reports) with 89.76% line coverage. Frontend: 33 Vitest component/a11y tests passing; Playwright E2E implemented for `./e2e` (requires the full stack).
