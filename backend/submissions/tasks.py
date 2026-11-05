"""Retention job: raw content lives only for the configured window (§14)."""

from __future__ import annotations

import logging

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)


@shared_task(name="submissions.purge_expired_raw_content")
def purge_expired_raw_content() -> int:
    """Clear encrypted raw content past retention_expires_at.

    The submission row and assessment survive (needed for history/report
    metadata); only the raw content is destroyed. Returns count purged.
    """
    from submissions.models import ScamSubmission

    expired = ScamSubmission.objects.filter(
        retention_expires_at__lt=timezone.now()
    ).exclude(raw_content_encrypted="")
    count = 0
    for sub in expired.iterator():
        sub.raw_content_encrypted = ""
        sub.save(update_fields=["raw_content_encrypted"])
        # Extracted values (phone, UPI, URLs…) are PII too; keep only the
        # keyed digest after the retention window.
        sub.indicators.update(normalised_value_encrypted="")
        count += 1
    if count:
        logger.info("retention_purged", extra={"count": count})
    return count
