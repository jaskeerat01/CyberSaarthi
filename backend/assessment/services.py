"""Assessment service: gather evidence, classify, store."""

from __future__ import annotations

import logging
from datetime import UTC

from assessment.engine import (
    EXPLANATION_KEYS,
    classify,
    evaluate_social_engineering,
    evaluate_technical,
    load_rules,
)
from assessment.models import ScanAssessment
from submissions.models import ScamSubmission

logger = logging.getLogger(__name__)

# Sources considered "reliable, verified threat intelligence" for
# CONFIRMED_MALICIOUS (spec §1). Reputation/aggregate signals (AbuseIPDB)
# count as technical evidence but never confirm on their own.
RELIABLE_PROVIDERS = {"fastpath", "phishtank", "virustotal", "openphish"}


def build_assessment(
    submission: ScamSubmission,
    observations: list[dict] | None = None,
    *,
    providers_ran: bool = True,
) -> dict:
    """Run deterministic classification. Returns assessment payload."""
    observations = observations or []
    text = submission.raw_content
    se_evidence, se_rules = evaluate_social_engineering(text)
    domains = [
        ind.normalised_value
        for ind in submission.indicators.all()
        if ind.indicator_type == "DOMAIN"
    ]
    # RDAP registration dates arrive in response_reference (ISO). The
    # youngest domain drives the TECH_NEW_DOMAIN weak signal; older-than-30d
    # registrations just show up as evidence. Malformed dates are ignored.
    from datetime import datetime

    domain_age_days: int | None = None
    for obs in observations:
        if obs.get("provider") != "rdap":
            continue
        ref = obs.get("response_reference")
        if not ref:
            continue
        try:
            registered = datetime.fromisoformat(str(ref))
        except ValueError:
            continue
        if registered.tzinfo is None:
            registered = registered.replace(tzinfo=UTC)
        age = (datetime.now(UTC) - registered).days
        domain_age_days = age if domain_age_days is None else min(domain_age_days, age)
    tech_evidence, tech_rules = evaluate_technical(
        domains, observations, domain_age_days=domain_age_days
    )

    has_match = any(o.get("outcome") == "MATCH" for o in observations)
    reliable_match = any(
        o.get("outcome") == "MATCH" and o.get("provider") in RELIABLE_PROVIDERS
        for o in observations
    )
    categories: set[str] = set()
    if reliable_match:
        categories.add("verified_threat_intel")
    elif has_match:
        # Reputation signals (e.g. AbuseIPDB) are technical evidence only
        categories.add("technical")
    if se_rules:
        categories.add("social_engineering")
    # NOTE: mere URL/domain presence (structural) is not a corroborating signal
    all_responded = providers_ran and (
        all(o.get("outcome") not in ("ERROR", "RATE_LIMITED") for o in observations)
        if observations
        else True
    )
    # Weak signals: a newly registered domain, or a non-reliable provider
    # MATCH (e.g. AbuseIPDB reputation). A verified match short-circuits to
    # CONFIRMED_MALICIOUS before this matters. NOTE: mere URL/domain presence
    # (TECH_URL_PRESENT) is structural, not a signal — counting it here would
    # label every URL scan SUSPICIOUS and make NO_KNOWN unreachable for URLs.
    has_weak = "TECH_NEW_DOMAIN" in tech_rules or "TECH_PROVIDER_MATCH" in tech_rules

    classification = classify(
        has_verified_match=reliable_match,
        corroborating_categories=categories,
        se_rule_count=len(se_rules),
        has_weak_technical=has_weak,
        all_providers_responded=all_responded,
    )
    confidence = (
        "HIGH" if reliable_match else ("MEDIUM" if categories or all_responded else "LOW")
    )
    ruleset = load_rules()
    return {
        "classification": classification,
        "technical_evidence": {"items": tech_evidence},
        "social_engineering_evidence": {"items": se_evidence},
        "confidence": confidence,
        "rule_ids": sorted(set(se_rules + tech_rules)),
        "ruleset_version": ruleset.get("version", "1.0"),
        "explanation_key": EXPLANATION_KEYS[classification],
    }


def store_assessment(
    submission: ScamSubmission,
    observations: list[dict] | None = None,
    *,
    providers_ran: bool = True,
) -> ScanAssessment:
    """Classify + persist. Idempotent per submission."""
    payload = build_assessment(submission, observations, providers_ran=providers_ran)
    assessment, _ = ScanAssessment.objects.update_or_create(
        submission=submission, defaults=payload
    )
    submission.status = "COMPLETED"
    submission.save(update_fields=["status"])
    logger.info("assessment_stored", extra={"scan_id": str(submission.id), "classification": assessment.classification})
    return assessment


def run_assessment(scan_id: str, *, providers_ran: bool = True) -> ScanAssessment:
    """Celery entrypoint: load submission, gather observations, assess."""
    submission = ScamSubmission.objects.get(id=scan_id)
    from indicators.models import IndicatorObservation, threat_indicators_for

    inds = list(submission.indicators.all())
    type_digests = {(i.indicator_type, bytes(i.digest)) for i in inds}
    threat_rows = threat_indicators_for(type_digests)
    obs = [
        {
            "provider": o.provider,
            "outcome": o.outcome,
            # RDAP registration dates travel in response_reference;
            # build_assessment derives the new-domain weak signal from it.
            "response_reference": o.response_reference or "",
        }
        for o in IndicatorObservation.objects.filter(indicator__in=threat_rows)
    ]
    # Local OpenPhish feed match (ingested every 12h — never per-request lookup).
    # OpenPhish entries are URLs, so only URL indicators are eligible.
    from intel.models import OpenPhishEntry

    url_digests = [bytes(i.digest) for i in inds if i.indicator_type == "URL"]
    feed_hits = OpenPhishEntry.matching_digests(url_digests)
    for i in inds:
        if i.indicator_type == "URL" and bytes(i.digest) in feed_hits:
            obs.append({"provider": "openphish", "outcome": "MATCH"})
    return store_assessment(submission, obs, providers_ran=providers_ran)
