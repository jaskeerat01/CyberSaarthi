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
        ident = request.META.get("REMOTE_ADDR", "unknown")
        return self.cache_format % {"scope": self.scope, "ident": ident}


class SubmissionRateThrottle(_IpScopedThrottle):
    """Scan submissions (default 30/hour)."""

    scope = "submissions"


class ReportRateThrottle(_IpScopedThrottle):
    """Report/PDF generation (default 10/hour)."""

    scope = "reports"
