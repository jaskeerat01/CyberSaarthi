"""Telegram webhook (Phase 2 stub — same API gateway, no separate pipeline)."""

from __future__ import annotations

import hmac
import logging

from django.conf import settings
from django.core.cache import cache
from drf_spectacular.utils import OpenApiTypes, extend_schema
from rest_framework.decorators import api_view
from rest_framework.request import Request
from rest_framework.response import Response

from core.problem_details import problem
from submissions.services import create_submission, start_scan_pipeline

logger = logging.getLogger(__name__)


@extend_schema(
    auth=[],
    request=OpenApiTypes.OBJECT,
    responses={200: OpenApiTypes.OBJECT, 202: OpenApiTypes.OBJECT},
    description=(
        "Telegram update webhook (Phase 2). Verifies the bot secret header, "
        "dedupes by update_id, and creates a scan from message text."
    ),
)
@api_view(["POST"])
def telegram_webhook(request: Request) -> Response:
    """POST /api/v1/telegram/webhook. Verifies secret token + dedupes by update_id."""
    secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    expected = getattr(settings, "TELEGRAM_WEBHOOK_SECRET", "")
    if not expected:
        # Fail closed: an unauthenticated public webhook must never create scans.
        logger.error("telegram_webhook_secret_not_configured")
        return problem("Telegram webhook is not configured", 503)
    if not hmac.compare_digest(secret, expected):
        return problem("Forbidden", 403)

    data = request.data if isinstance(request.data, dict) else {}
    raw_update_id = data.get("update_id")
    if isinstance(raw_update_id, bool) or not isinstance(raw_update_id, (int, str)):
        return problem("Missing or invalid update_id", 400)
    try:
        update_id = int(raw_update_id)
    except ValueError:
        return problem("Missing or invalid update_id", 400)
    dedupe_key = f"tg:update:{update_id}"
    # cache.add is atomic: concurrent retries of the same update cannot both
    # create a scan.
    if not cache.add(dedupe_key, "1", timeout=3600):
        return Response({"status": "duplicate"}, status=200)

    message = data.get("message")
    text = message.get("text", "") if isinstance(message, dict) else ""
    if not isinstance(text, str) or not text.strip():
        return Response({"status": "ignored"}, status=200)
    if len(text) > settings.MAX_INPUT_CHARS:
        return problem(
            "Validation failed",
            400,
            f"Message exceeds the {settings.MAX_INPUT_CHARS}-character limit.",
        )

    try:
        submission = create_submission(raw_content=text, channel="telegram")
    except ValueError as exc:
        cache.delete(dedupe_key)
        return problem("Validation failed", 400, str(exc))
    except Exception:
        # Release the claim so Telegram's retry is not silently dropped.
        cache.delete(dedupe_key)
        raise

    start_scan_pipeline(submission)
    submission.refresh_from_db(fields=["status"])
    return Response(
        {"scan_id": str(submission.id), "status": submission.status},
        status=202,
    )
