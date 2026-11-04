"""Celery → n8n webhook client. Authenticated; never consumes queues."""

from __future__ import annotations

import logging

import httpx
from django.conf import settings

from submissions.models import ScamSubmission

logger = logging.getLogger(__name__)


def invoke_investigation(scan_id: str, attempt: int = 1) -> bool:
    """Invoke n8n investigation workflow via webhook.

    Returns True if the webhook was actually called, False if no webhook is
    configured (providers unavailable). n8n is stateless lookup only; results
    arrive via /internal/ callbacks.
    """
    submission = ScamSubmission.objects.get(id=scan_id)
    indicators = [
        {"type": ind.indicator_type, "normalised_value": ind.normalised_value}
        for ind in submission.indicators.all()
    ]
    if not settings.N8N_WEBHOOK_URL:
        logger.warning("N8N_WEBHOOK_URL not configured — skipping n8n invocation")
        return False
    payload = {"scan_id": str(scan_id), "indicators": indicators, "attempt": attempt}
    try:
        resp = httpx.post(
            settings.N8N_WEBHOOK_URL,
            json=payload,
            headers={"X-CyberSathi-Service-Token": settings.N8N_WEBHOOK_TOKEN},
            timeout=10.0,
        )
        resp.raise_for_status()
    except httpx.HTTPError:
        # Propagate to Celery for retry → dead-letter on exhaustion
        logger.warning("n8n_invocation_failed", extra={"scan_id": scan_id, "attempt": attempt})
        raise
    logger.info("n8n_invoked", extra={"scan_id": scan_id, "attempt": attempt})
    return True
