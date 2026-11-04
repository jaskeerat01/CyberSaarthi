# ADR 0004: No numeric risk weights in MVP

## Status
Accepted

## Context
Arbitrary numeric weights create false precision and are hard to calibrate without a labelled dataset.

## Decision
- Classification is deterministic rule evaluation over a versioned YAML ruleset.
- Report three separate dimensions: technical evidence, social-engineering evidence, confidence (reliability + independent corroboration).
- Domain age is a weak signal; never alone produces HIGH_RISK.
- IP geolocation is never used as evidence of registration location.
- Numeric scoring may be introduced only after calibration on the evaluation dataset with held-out validation.

## Consequences
- Ruleset version stored with every assessment.
- Explanations are i18n keys tied to rule IDs — no free-form LLM advice.
