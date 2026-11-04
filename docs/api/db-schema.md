# Database Schema

PostgreSQL 16. All tables use UUID PKs where natural.

## Tables

### scam_submissions
| column | type | notes |
|---|---|---|
| id | UUID PK | |
| channel | VARCHAR(16) | web \| telegram |
| input_type | VARCHAR(16) | text \| url |
| raw_content | TEXT (encrypted) | Fernet at rest |
| content_hash | VARCHAR(64) | HMAC digest of content for idempotency |
| status | VARCHAR(16) | PENDING/RUNNING/COMPLETED/FAILED |
| reported_financial_loss | BOOL | triggers 1930 banner |
| created_at | TIMESTAMPTZ | |
| retention_expires_at | TIMESTAMPTZ | default +30d |

### extracted_indicators
| column | type | notes |
|---|---|---|
| id | UUID PK | |
| submission_id | FK → scam_submissions | |
| indicator_type | VARCHAR(16) | URL, DOMAIN, IP, PHONE, UPI, EMAIL |
| normalised_value | TEXT (encrypted) | |
| digest | BYTEA | HMAC-SHA256 |
| key_version | VARCHAR(32) | rotation support |

### threat_indicators
| column | type | notes |
|---|---|---|
| id | UUID PK | |
| indicator_type | VARCHAR(16) | |
| digest | BYTEA | |
| status | VARCHAR(16) | REPORTED, UNDER_REVIEW, CORROBORATED, CONFIRMED, EXPIRED |
| first_seen | TIMESTAMPTZ | |
| last_seen | TIMESTAMPTZ | |
| expires_at | TIMESTAMPTZ | |

**Constraint:** `UNIQUE(indicator_type, digest)` — no separate index on digest alone.

### indicator_observations
| column | type | notes |
|---|---|---|
| id | UUID PK | |
| indicator_id | FK → threat_indicators | |
| provider | VARCHAR(64) | |
| outcome | VARCHAR(16) | MATCH, NO_MATCH, ERROR, RATE_LIMITED, UNSUPPORTED |
| observed_at | TIMESTAMPTZ | |
| response_reference | TEXT | provider ref, redacted |

### scan_assessments
| column | type | notes |
|---|---|---|
| id | UUID PK | |
| submission_id | FK → scam_submissions | UNIQUE |
| classification | VARCHAR(32) | CONFIRMED_MALICIOUS, HIGH_RISK, SUSPICIOUS, NO_KNOWN_THREAT_DETECTED, INCONCLUSIVE |
| technical_evidence | JSONB | |
| social_engineering_evidence | JSONB | |
| confidence | VARCHAR(16) | HIGH/MEDIUM/LOW |
| rule_ids | TEXT[] | |
| ruleset_version | VARCHAR(32) | |
| explanation_key | VARCHAR(128) | i18n key |
| created_at | TIMESTAMPTZ | |

### workflow_events
| column | type | notes |
|---|---|---|
| id | UUID PK | |
| scan_id | FK → scam_submissions | |
| event_type | VARCHAR(64) | |
| attempt | INT | |
| payload_summary | JSONB | redacted |
| created_at | TIMESTAMPTZ | |

## Rules
- Promotion REPORTED → CORROBORATED/CONFIRMED requires trusted source or human review (enforced in code, logged).
- Concurrent upserts of same indicator are safe (`INSERT ... ON CONFLICT DO NOTHING` + state machine). Covered by concurrency tests.
