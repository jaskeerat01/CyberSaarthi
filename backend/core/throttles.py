"""Per-endpoint throttles (§14): stricter limits for submissions and reports.

ScopedRateThrottle reads ``view.throttle_scope``, which DRF does not copy onto
function-based views, so these subclasses pin scope + cache key explicitly.
Rates come from REST_FRAMEWORK['DEFAULT_THROTTLE_RATES'] in settings.
"""

from rest_framework.throttling import SimpleRateThrottle


class _IpScopedThrottle(SimpleRateThrottle):
    """Per-IP throttle with a fixed scope."""

    scope: str = "default"

    def get_cache_key(self, request, view):
        # The frontend nginx proxy sets X-Real-IP (to the client IP) and
        # appends to X-Forwarded-For; REMOTE_ADDR would be the proxy for
        # every client, collapsing all buckets into one. X-Real-IP is
        # overwritten by nginx, so it cannot be spoofed through the proxy.
        # Fall back to the first forwarded hop, then REMOTE_ADDR.
        forwarded = (request.META.get("HTTP_X_FORWARDED_FOR") or "").split(",")[0].strip()
        ident = (
            request.META.get("HTTP_X_REAL_IP") or forwarded or request.META.get("REMOTE_ADDR", "unknown")
        )
        return self.cache_format % {"scope": self.scope, "ident": ident}


class SubmissionRateThrottle(_IpScopedThrottle):
    """Scan submissions (default 30/hour)."""

    scope = "submissions"


class ReportRateThrottle(_IpScopedThrottle):
    """Report/PDF generation (default 10/hour)."""

    scope = "reports"
