"""Deterministic risk engine. Rules decide classification — never the LLM."""

from __future__ import annotations

from pathlib import Path

import yaml

_RULES_PATH = Path(__file__).parent / "rules.yaml"
_rules_cache: dict | None = None


def load_rules() -> dict:
    """Load versioned YAML ruleset."""
    global _rules_cache
    if _rules_cache is None:
        with _RULES_PATH.open() as fh:
            _rules_cache = yaml.safe_load(fh)
    return _rules_cache


def evaluate_social_engineering(text: str, domain_age_days: int | None = None) -> tuple[list[dict], list[str]]:
    """Evaluate SE rules. Returns (evidence list, matched rule IDs)."""
    ruleset = load_rules()
    evidence: list[dict] = []
    matched: list[str] = []
    lowered = text.lower()
    for rule in ruleset["rules"]:
        if rule["category"] != "social_engineering":
            continue
        hits = [p for p in rule.get("patterns", []) if p.lower() in lowered]
        if hits:
            evidence.append({"rule_id": rule["id"], "hits": hits})
            matched.append(rule["id"])
    return evidence, matched


def evaluate_technical(
    domains: list[str],
    observations: list[dict],
    domain_age_days: int | None = None,
) -> tuple[list[dict], list[str]]:
    """Evaluate technical evidence from provider observations + structure."""
    evidence: list[dict] = []
    matched: list[str] = []
    # Provider matches
    for obs in observations:
        if obs.get("outcome") == "MATCH":
            evidence.append({"provider": obs.get("provider"), "outcome": "MATCH"})
    if any(o.get("outcome") == "MATCH" for o in observations):
        matched.append("TECH_PROVIDER_MATCH")
    if domains:
        evidence.append({"domains": domains})
        matched.append("TECH_URL_PRESENT")
    if domain_age_days is not None and domain_age_days < 30:
        # Weak signal only — never alone produces HIGH_RISK
        evidence.append({"domain_age_days": domain_age_days, "signal": "new_domain"})
        matched.append("TECH_NEW_DOMAIN")
    return evidence, matched


def classify(
    *,
    has_verified_match: bool,
    corroborating_categories: set[str],
    se_rule_count: int,
    has_weak_technical: bool,
    all_providers_responded: bool,
) -> str:
    """Classification in spec order, first match wins.

    - CONFIRMED_MALICIOUS: matched to reliable, verified threat intelligence.
      ``has_verified_match`` must come from a reliable source (see
      RELIABLE_PROVIDERS in assessment.services); reputation signals such as
      AbuseIPDB are technical evidence, not verified threat intelligence.
    - HIGH_RISK: >=2 independent corroborating signals from different categories
    - SUSPICIOUS: strong SE signals, or single weak technical signal
    - NO_KNOWN_THREAT_DETECTED: no matches/signals + all providers responded
    - INCONCLUSIVE: insufficient evidence / providers unavailable
    """
    if has_verified_match:
        return "CONFIRMED_MALICIOUS"
    if len(corroborating_categories) >= 2:
        return "HIGH_RISK"
    if se_rule_count >= 1 or has_weak_technical:
        return "SUSPICIOUS"
    if all_providers_responded:
        return "NO_KNOWN_THREAT_DETECTED"
    return "INCONCLUSIVE"


# i18n explanation keys tied to rule IDs — no free-form advice generation
EXPLANATION_KEYS = {
    "CONFIRMED_MALICIOUS": "assessment.confirmed_malicious",
    "HIGH_RISK": "assessment.high_risk",
    "SUSPICIOUS": "assessment.suspicious",
    "NO_KNOWN_THREAT_DETECTED": "assessment.no_known_threat",
    "INCONCLUSIVE": "assessment.inconclusive",
}
