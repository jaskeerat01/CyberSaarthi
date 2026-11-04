"""Health endpoints + Prometheus metrics skeleton."""

from __future__ import annotations

from django.db import connection
from django.http import JsonResponse
from django.views.decorators.http import require_GET

try:
    from prometheus_client import Counter, Histogram, generate_latest

    REQUEST_LATENCY = Histogram("cybersathi_request_latency_seconds", "Request latency")
    PROVIDER_OUTCOMES = Counter("cybersathi_provider_outcomes_total", "Provider outcomes", ["provider", "outcome"])
except Exception:  # noqa: BLE001 — probe must never crash  # pragma: no cover
    REQUEST_LATENCY = None  # type: ignore
    PROVIDER_OUTCOMES = None  # type: ignore


@require_GET
def healthz(request):
    """Liveness probe."""
    return JsonResponse({"status": "ok"})


@require_GET
def readyz(request):
    """Readiness probe — DB + Redis connectivity."""
    try:
        with connection.cursor() as cur:
            cur.execute("SELECT 1")
        db_ok = True
    except Exception:  # noqa: BLE001
        db_ok = False
    try:
        from django.core.cache import cache

        cache.set("readyz:ping", "1", timeout=5)
        redis_ok = bool(cache.get("readyz:ping"))
    except Exception:  # noqa: BLE001
        redis_ok = False
    status = 200 if (db_ok and redis_ok) else 503
    return JsonResponse({"db": db_ok, "redis": redis_ok}, status=status)


@require_GET
def metrics(request):
    """Prometheus metrics endpoint."""
    from django.http import HttpResponse

    if PROVIDER_OUTCOMES is None:
        return HttpResponse("", status=503)
    return HttpResponse(generate_latest(), content_type="text/plain")
