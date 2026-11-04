# Automation

n8n investigation workflow for Citizen CyberSathi.

## Workflows

| File | Description | Status |
|---|---|---|
| `cybersathi-scan-investigation.json` | Webhook-triggered investigation (PhishTank + RDAP + AbuseIPDB lookups) | **Pending creation via MCP** (see below) |

## Pending n8n workflow (MCP)

The workflow "CyberSathi - Scan Investigation" has NOT been created yet (user deferred).
To create it later:

1. Inspect instance via MCP: search workflows by name/tag, list credentials.
2. Build with nodes: Webhook (header auth) → Validate → Switch by type → parallel provider calls (5s timeout, continueOnFail) → Merge → Send enrichment → Send complete → Error Trigger.
3. Test with fixtures in `fixtures/` (no live calls): all-success, timeout, 429, all-fail, malformed, missing token.
4. Publish only after all tests pass. Export JSON here with secrets stripped; gitleaks before commit.
5. Record workflow ID + test results here.

Design doc: `docs/n8n-design.md`.

## Fixtures

See `fixtures/README.md`. All labelled synthetic — CI never calls live providers.
