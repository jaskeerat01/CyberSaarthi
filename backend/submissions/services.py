"""Submission service: idempotency, extraction, fast-path handoff."""

from __future__ import annotations

import logging

from django.conf import settings
from django.db import transaction

from core.crypto import encrypt, hmac_digest
from submissions.models import ExtractedIndicator, ScamSubmission, WorkflowEvent

from . import normalisation as norm

logger = logging.getLogger(__name__)


def create_submission(
    raw_content: str,
    channel: str = "web",
    reported_financial_loss: bool = False,
    *,
    normalised_text: str | None = None,
    content_digest: bytes | None = None,
) -> ScamSubmission:
    """Create a submission + extract indicators. Idempotency handled by caller via content hash.

    ``normalised_text``/``content_digest`` let callers that already normalised
    the input (e.g. create_scan, for the dedupe lookup) avoid a second
    normalisation pass and HMAC over the same text.
    """
    text = (
        normalised_text
        if normalised_text is not None
        else norm.normalise_text(raw_content, max_chars=settings.MAX_INPUT_CHARS)
    )
    if content_digest is None:
        content_digest, _ = hmac_digest(text)
    # Extract once: each extractor is a regex pass over the whole message and
    # the URL list is also needed to decide input_type.
    urls = norm.extract_urls(text)

    indicators: list[tuple[str, str]] = []
    for url in urls:
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

    # One INSERT for the submission (the raw_content setter also stamps
    # retention_expires_at) and one bulk INSERT for the indicators instead of
    # a get_or_create round-trip per indicator.
    with transaction.atomic():
        submission = ScamSubmission(
            channel=channel,
            input_type="url" if urls else "text",
            reported_financial_loss=reported_financial_loss,
            content_hash=content_digest,
        )
        submission.raw_content = text
        submission.save()

        rows: list[ExtractedIndicator] = []
        for itype, value in indicators:
            digest, version = hmac_digest(value)
            rows.append(
                ExtractedIndicator(
                    submission=submission,
                    indicator_type=itype,
                    digest=digest,
                    key_version=version,
                    normalised_value_encrypted=encrypt(value),
                )
            )
        # ignore_conflicts covers the unique(submission, type, digest) guard;
        # the de-duplication above should already make this a no-op.
        ExtractedIndicator.objects.bulk_create(rows, ignore_conflicts=True)

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
