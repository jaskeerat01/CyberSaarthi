"""Scan API views (DRF)."""

from __future__ import annotations

import logging

from django.conf import settings
from django.core.cache import cache
from drf_spectacular.utils import OpenApiTypes, extend_schema
from rest_framework import status
from rest_framework.decorators import api_view, throttle_classes
from rest_framework.request import Request
from rest_framework.response import Response

from assessment.models import ScanAssessment
from core.problem_details import problem
from core.throttles import SubmissionRateThrottle

from . import normalisation as norm
from .models import ScamSubmission
from .serializers import ScanCreateSerializer, ScanDetailSerializer
from .services import create_submission, find_existing_by_content, log_event

logger = logging.getLogger(__name__)

IDEMPOTENCY_WINDOW_SECONDS = 900  # 15 minutes


def _scan_payload(submission: ScamSubmission) -> dict:
    return {
        "scan_id": str(submission.id),
        "status": submission.status,
        "reported_financial_loss": submission.reported_financial_loss,
    }


@extend_schema(request=ScanCreateSerializer, responses={202: ScanDetailSerializer})
@api_view(["POST"])
@throttle_classes([SubmissionRateThrottle])
def create_scan(request: Request) -> Response:
    """POST /api/v1/scans — 202 Accepted with scan_id. Idempotency-Key dedupes."""
    serializer = ScanCreateSerializer(data=request.data)
    if not serializer.is_valid():
        return problem("Validation failed", 400, str(serializer.errors))
    data = serializer.validated_data

    # Idempotency-Key header (spec §6): replay returns the existing scan
    idem_key = request.headers.get("Idempotency-Key", "")
    if idem_key:
        cached_id = cache.get(f"idem:{idem_key}")
        if cached_id:
            try:
                existing = ScamSubmission.objects.get(id=cached_id)
                return Response(_scan_payload(existing), status=status.HTTP_202_ACCEPTED)
            except ScamSubmission.DoesNotExist:
                cache.delete(f"idem:{idem_key}")

    # Content-hash dedupe: identical submissions within the window
    text = norm.normalise_text(data["raw_content"], max_chars=settings.MAX_INPUT_CHARS)
    from core.crypto import hmac_digest

    digest, _ = hmac_digest(text)
    existing = find_existing_by_content(digest)
    if existing:
        return Response(_scan_payload(existing), status=status.HTTP_202_ACCEPTED)

    submission = create_submission(
        raw_content=data["raw_content"],
        channel=data.get("channel", "web"),
        reported_financial_loss=data.get("reported_financial_loss", False),
    )
    if idem_key:
        cache.set(f"idem:{idem_key}", str(submission.id), timeout=IDEMPOTENCY_WINDOW_SECONDS)
    log_event(submission, "scan_queued")

    # Fast-path then Celery slow-path
    from intel.fastpath import fast_path_check

    fast_result = fast_path_check(submission)
    if fast_result is None:
        from config.celery import investigate_scan

        investigate_scan.delay(str(submission.id))
        log_event(submission, "slow_path_enqueued")
    else:
        from assessment.services import store_assessment

        store_assessment(submission, fast_result)

    return Response(_scan_payload(submission), status=status.HTTP_202_ACCEPTED)


@extend_schema(
    responses={200: ScanDetailSerializer, 204: OpenApiTypes.OBJECT},
    description=(
        "GET: scan status plus assessment (classification, evidence, disclaimer). "
        "DELETE: user-initiated deletion of the submission and its raw content (spec §6)."
    ),
)
@api_view(["GET", "DELETE"])
def scan_detail(request: Request, scan_id: str) -> Response:
    """GET /api/v1/scans/{scan_id} — status + assessment.
    DELETE /api/v1/scans/{scan_id} — user-initiated deletion.
    """
    try:
        submission = ScamSubmission.objects.get(id=scan_id)
    except (ScamSubmission.DoesNotExist, ValueError):
        return problem("Scan not found", 404)

    if request.method == "DELETE":
        log_event(submission, "scan_deleted_by_user")
        submission.delete_content()
        submission.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    payload = _scan_payload(submission)
    assessment = ScanAssessment.objects.filter(submission=submission).first()
    if assessment:
        payload.update(
            {
                "classification": assessment.classification,
                "technical_evidence": assessment.technical_evidence,
                "social_engineering_evidence": assessment.social_engineering_evidence,
                "confidence": assessment.confidence,
                "rule_ids": assessment.rule_ids,
                "ruleset_version": assessment.ruleset_version,
                "explanation_key": assessment.explanation_key,
                "disclaimer": (
                    "NO_KNOWN_THREAT_DETECTED does not guarantee safety or legitimacy. "
                    "Always exercise caution with suspicious content."
                    if assessment.classification == "NO_KNOWN_THREAT_DETECTED"
                    else ""
                ),
            }
        )
    return Response(payload)


@extend_schema(responses={200: OpenApiTypes.OBJECT})
@api_view(["GET"])
def get_evidence(request: Request, scan_id: str) -> Response:
    """GET /api/v1/scans/{scan_id}/evidence."""
    try:
        submission = ScamSubmission.objects.get(id=scan_id)
    except (ScamSubmission.DoesNotExist, ValueError):
        return problem("Scan not found", 404)
    indicators = list(submission.indicators.all())
    payload_indicators = [
        {"type": ind.indicator_type, "digest": ind.digest.hex()[:16] + "…"}
        for ind in indicators
    ]
    from indicators.models import IndicatorObservation, ThreatIndicator

    # Key observations on (type, digest) pairs — digest alone could collide
    # across indicator types (spec: UNIQUE(indicator_type, digest))
    type_digests = {(ind.indicator_type, bytes(ind.digest)) for ind in indicators}
    threat_rows = ThreatIndicator.objects.filter(
        indicator_type__in=[t for t, _ in type_digests],
        digest__in=[d for _, d in type_digests],
    )
    observations = [
        {
            "provider": obs.provider,
            "outcome": obs.outcome,
            "observed_at": obs.observed_at.isoformat() if obs.observed_at else None,
        }
        for obs in IndicatorObservation.objects.filter(indicator__in=threat_rows)
    ]
    assessment = ScanAssessment.objects.filter(submission=submission).first()
    return Response(
        {
            "scan_id": str(submission.id),
            "indicators": payload_indicators,
            "observations": observations,
            "assessment": {
                "classification": assessment.classification,
                "rule_ids": assessment.rule_ids,
                "ruleset_version": assessment.ruleset_version,
            }
            if assessment
            else None,
        }
    )
