"""Fast-path lookup: Redis cache → PostgreSQL verified indicators.

Target: low latency measured as P50/P95. Never "zero latency".

Only a verified indicator (status CORROBORATED or CONFIRMED) resolves via the
fast path. A NO_MATCH — fresh or cached — always falls through to the slow
path, because provider lookups have not been performed yet.
"""

from __future__ import annotations

import logging

from django.core.cache import cache

from indicators.models import ThreatIndicator, ThreatIndicatorStatus
from submissions.models import ScamSubmission

logger = logging.getLogger(__name__)


def fast_path_check(submission: ScamSubmission) -> list[dict] | None:
    """Return observations if ALL indicators are verified matches, else None.

    None means: proceed to slow-path (Celery → n8n).
    """
    observations: list[dict] = []
    unresolved = 0

    for ind in submission.indicators.all():
        cache_key = f"ti:{ind.indicator_type}:{ind.digest.hex()[:32]}"
        cached = cache.get(cache_key)
        if cached is None:
            hit = ThreatIndicator.objects.filter(
                indicator_type=ind.indicator_type,
                digest=ind.digest,
                status__in=[ThreatIndicatorStatus.CORROBORATED, ThreatIndicatorStatus.CONFIRMED],
            ).first()
            cached = "MATCH" if hit else "NO_MATCH"
            cache.set(cache_key, cached, timeout=300)

        if cached == "MATCH":
            observations.append(
                {"provider": "fastpath", "outcome": "MATCH", "indicator_type": ind.indicator_type}
            )
        else:
            # NO_MATCH (fresh or cached) = unresolved → slow path required.
            unresolved += 1

    if unresolved:
        return None  # Slow-path needed
    return observations or None
