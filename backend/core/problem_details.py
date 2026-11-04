"""RFC 9457 Problem Details helpers."""

from __future__ import annotations

from django.http import JsonResponse


def problem(title: str, status: int, detail: str = "", type_: str = "about:blank", instance: str = "") -> JsonResponse:
    """Build RFC 9457 response."""
    return JsonResponse(
        {"type": type_, "title": title, "status": status, "detail": detail, "instance": instance},
        status=status,
        content_type="application/problem+json",
    )
