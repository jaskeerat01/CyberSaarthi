import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate } from 'k6/metrics';

/**
 * Fast-path load test (docs/evaluation/test-plan.md).
 *
 * Measures P50/P95 for POST /api/v1/scans when every indicator in the
 * submission is already verified (fast path resolves without n8n).
 * Latency is REPORTED via summaryTrendStats — never asserted as "zero latency".
 *
 * Prerequisite: seed the indicator BEFORE running — see load/README.md.
 *
 *   k6 run load/k6-fastpath.js \
 *     -e BASE_URL=http://localhost:8000 \
 *     -e SEED_URL=https://seeded-bad.example/login
 */

const BASE = __ENV.BASE_URL || 'http://localhost:8000';
const SEED_URL = __ENV.SEED_URL || 'https://seeded-bad.example/login';

const serverErrors = new Rate('server_errors');
const fastPathLikely = new Counter('responses_202');

export const options = {
  scenarios: {
    // Fast path: unique raw_content each request (so content-hash dedupe never
    // short-circuits) but the same seeded URL indicator (so the verified
    // indicator cache/DB hit serves the fast path).
    fast_path: {
      executor: 'constant-arrival-rate',
      rate: Number(__ENV.RATE || 20), // requests per second
      timeUnit: '1s',
      duration: __ENV.DURATION || '1m',
      preAllocatedVUs: 50,
      maxVUs: 200,
      exec: 'fastPathScan',
    },
    // Control scenario: no indicators at all (no fast-path lookup, no n8n).
    baseline: {
      executor: 'constant-arrival-rate',
      rate: Number(__ENV.BASELINE_RATE || 5),
      timeUnit: '1s',
      duration: __ENV.DURATION || '1m',
      preAllocatedVUs: 20,
      maxVUs: 50,
      exec: 'baselineScan',
      startTime: '10s',
    },
  },
  // Measurement only: report avg/p50/p90/p95/max of latency trends.
  summaryTrendStats: ['avg', 'p(50)', 'p(90)', 'p(95)', 'max'],
  thresholds: {
    // Availability gates — latency itself is measured, not gated (§ test-plan).
    http_req_failed: ['rate<0.01'],
    server_errors: ['rate<0.01'],
    checks: ['rate>0.95'],
  },
  discardResponseBodies: true,
};

function postScan(payload) {
  const res = http.post(`${BASE}/api/v1/scans`, JSON.stringify(payload), {
    headers: {
      'Content-Type': 'application/json',
      // Unique per request → idempotency cache never replays an old response.
      'Idempotency-Key': `k6-${__VU}-${__ITER}-${Date.now()}`,
    },
    tags: { name: 'POST /api/v1/scans' },
  });
  const ok = check(res, {
    'status is 202': (r) => r.status === 202,
    'returns scan_id': (r) => Boolean(r.json && r.json('scan_id')),
  });
  serverErrors.add(res.status >= 500);
  if (res.status === 202) fastPathLikely.add(1);
  return ok;
}

// Scenario 1 — fast path (seeded URL + unique noise text per request).
export function fastPathScan() {
  postScan({
    raw_content: `Check ${SEED_URL} now (ref ${__VU}-${__ITER}-${Date.now()})`,
    reported_financial_loss: false,
    channel: 'web',
  });
  sleep(0.05);
}

// Scenario 2 — baseline with no indicators (structural rules only).
export function baselineScan() {
  postScan({
    raw_content: `Routine message ${__VU}-${__ITER}-${Date.now()} with no links at all`,
    reported_financial_loss: false,
    channel: 'web',
  });
  sleep(0.1);
}

export function handleSummary(data) {
  // Print the two numbers the test plan asks for explicitly.
  const fp = data.metrics.http_req_duration.values;
  return {
    stdout: JSON.stringify(
      {
        note: 'Measured, not guaranteed — see docs/limitations.md',
        http_req_duration_all: {
          p50_ms: fp['p(50)'],
          p95_ms: fp['p(95)'],
        },
        checks_rate: data.metrics.checks?.values?.rate,
        failed_rate: data.metrics.http_req_failed?.values?.rate,
      },
      null,
      2,
    ),
  };
}
