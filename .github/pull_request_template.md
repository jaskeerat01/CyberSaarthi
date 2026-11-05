## Summary

<!-- What does this PR change, and why? -->

## Type

- [ ] feat — new functionality
- [ ] fix — bug fix
- [ ] docs — documentation only
- [ ] test — tests only
- [ ] chore — tooling, deps, CI

## Checklist (spec §17)

- [ ] Conventional Commit message used
- [ ] `ruff check .` and `mypy .` pass (backend)
- [ ] `pytest` passes; no coverage regression (target ≥80%)
- [ ] `npm run lint`, `npx tsc --noEmit`, `npm test` pass (frontend)
- [ ] No secrets, tokens, or API keys added (gitleaks runs in CI)
- [ ] New/changed endpoints documented in `docs/openapi.yaml` (validate with `manage.py spectacular --validate`)
- [ ] User-facing strings added to **both** `en` and `hi` resources
- [ ] Docs/ADRs updated where behaviour or decisions changed
