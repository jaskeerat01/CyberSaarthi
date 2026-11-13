"""Fast-path lookup: Redis cache → PostgreSQL verified indicators.

Target: low latency measured as P50/P95. Never "zero latency".

Only a verified indicator (status CORROBORATED or CONFIRMED) resolves via the
fast path. A NO_MATCH — fresh or cached — always falls through to the slow
path, because provider lookups have not been performed yet.
"""

from __future__ import annotations

import logging

from django.core.cache import cache

from indicators.models import (
    ThreatIndicatorStatus,
    threat_indicators_for,
)
from submissions.models import ScamSubmission

logger = logging.getLogger(__name__)

# Verified statuses — anything else must go through the slow path.
_VERIFIED = [ThreatIndicatorStatus.CORROBORATED, ThreatIndicatorStatus.CONFIRMED]

# Fast-path cache TTL (seconds). Short because promotions change the answer.
_CACHE_TTL = 300


def _statuses(indicator_type: str, digest: bytes) -> str:
    """Cache key scoped by indicator type (a digest alone is not unique)."""
    return f"ti:{indicator_type}:{digest.hex()[:32]}"


def fast_path_check(submission: ScamSubmission) -> list[dict] | None:
    """Return observations if ALL indicators are verified matches, else None.

    None means: proceed to slow-path (Celery → n8n).

    Cache misses are resolved with a single batched query instead of one
    SELECT per indicator, so a dense scan does not turn into N round-trips.
    """
    indicators = [
        (ind.indicator_type, bytes(ind.digest)) for ind in submission.indicators.all()
    ]
    if not indicators:
        return None

    resolved: dict[tuple[str, bytes], bool] = {}
    misses: list[tuple[str, bytes, str]] = []
    for indicator_type, digest in indicators:
        key = _statuses(indicator_type, digest)
        cached = cache.get(key)
        if cached is None:
            misses.append((indicator_type, digest, key))
        else:
            resolved[(indicator_type, digest)] = cached == "MATCH"

    if misses:
        verified = {
            (row.indicator_type, bytes(row.digest))
            for row in threat_indicators_for(
                [(indicator_type, digest) for indicator_type, digest, _ in misses]
            ).filter(status__in=_VERIFIED)
        }
        for indicator_type, digest, key in misses:
            matched = (indicator_type, digest) in verified
            cache.set(key, "MATCH" if matched else "NO_MATCH", timeout=_CACHE_TTL)
            resolved[(indicator_type, digest)] = matched

    unresolved = sum(1 for matched in resolved.values() if not matched)
    if unresolved:
        return None  # Slow-path needed

    observations = [
        {"provider": "fastpath", "outcome": "MATCH", "indicator_type": indicator_type}
        for indicator_type, _digest in indicators
    ]
    return observations or None
