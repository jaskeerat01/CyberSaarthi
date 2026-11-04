# Evaluation Report (MVP)

Status: pending dataset. Metrics to report once a labelled dataset is available (see `datasets/sources.md`):

- Precision, recall, false-positive rate
- Entity extraction accuracy
- Workflow success rate, retry outcomes
- Cache hit ratio, provider-outage behaviour
- PDF generation success rate

Backend unit/API tests: 57 passing (normalisation, classification, indicators, providers, API, reports).
Frontend component tests + Playwright E2E implemented; run after `npm install`.
