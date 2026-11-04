"""Submission service: idempotency, extraction, fast-path handoff."""

from __future__ import annotations

import logging

from django.conf import settings
from django.db import transaction

from core.crypto import hmac_digest
from submissions.models import ExtractedIndicator, ScamSubmission, WorkflowEvent

from . import normalisation as norm

logger = logging.getLogger(__name__)


def create_submission(raw_content: str, channel: str = "web", reported_financial_loss: bool = False) -> ScamSubmission:
    """Create a submission + extract indicators. Idempotency handled by caller via content hash."""
    text = norm.normalise_text(raw_content, max_chars=settings.MAX_INPUT_CHARS)
    content_digest, _ = hmac_digest(text)

    with transaction.atomic():
        submission = ScamSubmission.objects.create(
            channel=channel,
            input_type="url" if norm.extract_urls(text) else "text",
            reported_financial_loss=reported_financial_loss,
        )
        submission.raw_content = text
        submission.content_hash = content_digest
        submission.save()

        indicators: list[tuple[str, str]] = []
        for url in norm.extract_urls(text):
            indicators.append(("URL", url))
            domain = norm.extract_domain(url)
            if domain:
                indicators.append(("DOMAIN", domain))
        for email in norm.extract_emails(text):
            indicators.append(("EMAIL", email))
        for phone in norm.extract_phones(text):
            indicators.append(("PHONE", phone))
        for upi in norm.extract_upi_ids(text):
            indicators.append(("UPI", upi))
        for ip in norm.extract_ips(text):
            indicators.append(("IP", ip))

        for itype, value in indicators:
            digest, version = hmac_digest(value)
            ExtractedIndicator.objects.get_or_create(
                submission=submission,
                indicator_type=itype,
                digest=digest,
                defaults={"key_version": version},
            )
            # Set encrypted value on the (possibly existing) row
            ExtractedIndicator.objects.filter(
                submission=submission, indicator_type=itype, digest=digest
            ).update(normalised_value_encrypted=submission.raw_content_encrypted)
            # NOTE: stores normalised value encrypted (demo: reuses content encryption)
            obj = ExtractedIndicator.objects.get(
                submission=submission, indicator_type=itype, digest=digest
            )
            obj.normalised_value = value
            obj.save(update_fields=["normalised_value_encrypted"])

        WorkflowEvent.objects.create(
            scan=submission,
            event_type="submission_created",
            payload_summary={"indicator_count": len(indicators)},
        )
    logger.info("submission_created", extra={"scan_id": str(submission.id)})
    return submission


def find_existing_by_content(content_digest: bytes, window_minutes: int = 15) -> ScamSubmission | None:
    """Idempotency window: identical submissions return the existing scan."""
    from django.utils import timezone

    cutoff = timezone.now() - timezone.timedelta(minutes=window_minutes)
    return ScamSubmission.objects.filter(content_hash=content_digest, created_at__gte=cutoff).first()


def log_event(scan: ScamSubmission, event_type: str, attempt: int = 1, summary: dict | None = None) -> None:
    """Write a workflow_events audit record."""
    WorkflowEvent.objects.create(
        scan=scan, event_type=event_type, attempt=attempt, payload_summary=summary or {}
    )
