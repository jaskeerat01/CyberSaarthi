"""Celery app. Owns job state, retries, timeouts, DLQ."""

from __future__ import annotations

import json
import logging
import os

from celery import Celery
from celery.signals import task_failure

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

logger = logging.getLogger(__name__)

app = Celery("cybersathi")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

DLQ_KEY = "cybersathi:dead-letter"


@app.task(bind=True, max_retries=2, default_retry_delay=30)
def investigate_scan(self, scan_id: str) -> bool:
    """Invoke n8n investigation webhook; results arrive via /internal/ callbacks.

    Celery owns retries/timeouts. If the webhook is unreachable the task
    retries, then fails into the dead-letter queue (see task_failure handler).
    """
    from intel.n8n_client import invoke_investigation

    invoked = invoke_investigation(scan_id, attempt=self.request.retries + 1)
    if not invoked:
        # No webhook configured — providers never ran: record INCONCLUSIVE.
        from assessment.services import run_assessment

        run_assessment(scan_id, providers_ran=False)
        return False
    # Providers run asynchronously in n8n; assessment is stored when
    # n8n posts to /internal/scans/{id}/complete.
    return True


@task_failure.connect
def _dead_letter(
    sender=None,
    task_id: str | None = None,
    exception: Exception | None = None,
    **kwargs,
) -> None:
    """Push failed tasks to a Redis dead-letter list (§16).

    Payload is redacted: task id/name and a truncated error string only —
    never arguments or raw submission content.
    """
    try:
        import redis as redis_lib
        from django.conf import settings

        client = redis_lib.from_url(settings.CELERY_BROKER_URL, socket_connect_timeout=2)
        client.lpush(
            DLQ_KEY,
            json.dumps(
                {
                    "task_id": task_id,
                    "task_name": getattr(sender, "name", str(sender)),
                    "error": str(exception)[:200],
                }
            ),
        )
        client.ltrim(DLQ_KEY, 0, 999)
        logger.error("task_dead_lettered", extra={"task_id": task_id})
    except Exception:
        logger.exception("dlq_push_failed")
