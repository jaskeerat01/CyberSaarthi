"""Security headers, CSP, and redacting JSON logging middleware."""

from __future__ import annotations

import logging
import time

from core.views import REQUEST_LATENCY

logger = logging.getLogger(__name__)

_REDACTED = ("phone", "upi", "url", "content")


class SecurityHeadersMiddleware:
    """Adds strict security headers; no inline scripts (CSP)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
        )
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response


class JsonLoggingMiddleware:
    """Structured logging with PII redaction — never log raw content/URLs."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        start = time.perf_counter()
        response = self.get_response(request)
        elapsed = time.perf_counter() - start

        if REQUEST_LATENCY is not None:
            REQUEST_LATENCY.observe(elapsed)

        scan_id = getattr(request, "scan_id", None) or request.path
        logger.info(
            "request",
            extra={
                "method": request.method,
                "path": request.path.split("?")[0],
                "scan_id": str(scan_id),
                "status": response.status_code,
                "latency_ms": round(elapsed * 1000, 2),
            },
        )
        return response
