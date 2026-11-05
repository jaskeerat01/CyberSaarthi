"""Submission service: idempotency, extraction, fast-path handoff."""

from __future__ import annotations

import logging

from django.conf import settings
from django.db import transaction

from core.crypto import encrypt, hmac_digest
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

        # The n8n contract accepts at most 50 indicators; de-duplicate and cap
        # here so a dense message cannot make the workflow reject the scan and
        # leave it stuck before completion.
        seen: set[tuple[str, str]] = set()
        unique_indicators: list[tuple[str, str]] = []
        for pair in indicators:
            if pair not in seen:
                seen.add(pair)
                unique_indicators.append(pair)
        indicators = unique_indicators[:50]

        for itype, value in indicators:
            digest, version = hmac_digest(value)
            ExtractedIndicator.objects.get_or_create(
                submission=submission,
                indicator_type=itype,
                digest=digest,
                defaults={
                    "key_version": version,
                    "normalised_value_encrypted": encrypt(value),
                },
            )

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


def start_scan_pipeline(submission: ScamSubmission) -> None:
    """Resolve via the fast path, otherwise enqueue the Celery/n8n slow path.

    Shared by the web API and Telegram webhook so every entry point runs the
    same investigation pipeline.
    """
    from assessment.services import store_assessment
    from config.celery import investigate_scan
    from intel.fastpath import fast_path_check

    fast_result = fast_path_check(submission)
    if fast_result is None:
        investigate_scan.delay(str(submission.id))
        log_event(submission, "slow_path_enqueued")
        return
    store_assessment(submission, fast_result)
    log_event(submission, "fast_path_resolved")
