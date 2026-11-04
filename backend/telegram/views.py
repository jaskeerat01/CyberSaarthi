"""Telegram webhook (Phase 2 stub — same API gateway, no separate pipeline)."""

from __future__ import annotations

import hmac

from django.conf import settings
from django.core.cache import cache
from drf_spectacular.utils import OpenApiTypes, extend_schema
from rest_framework.decorators import api_view
from rest_framework.request import Request
from rest_framework.response import Response

from core.problem_details import problem
from submissions.services import create_submission


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
    if expected and not hmac.compare_digest(secret, expected):
        return problem("Forbidden", 403)

    update_id = request.data.get("update_id")
    if update_id is None:
        return problem("Missing update_id", 400)
    dedupe_key = f"tg:update:{update_id}"
    if cache.get(dedupe_key):
        return Response({"status": "duplicate"}, status=200)
    cache.set(dedupe_key, "1", timeout=3600)

    message = request.data.get("message", {})
    text = message.get("text", "")
    if text:
        submission = create_submission(raw_content=text, channel="telegram")
        return Response({"scan_id": str(submission.id), "status": submission.status}, status=202)
    return Response({"status": "ignored"}, status=200)
