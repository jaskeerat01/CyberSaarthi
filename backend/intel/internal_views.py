"""Internal endpoints for n8n callbacks. Service-token auth, never public."""

from __future__ import annotations

import hmac
import logging

from django.conf import settings
from drf_spectacular.utils import OpenApiTypes, extend_schema
from rest_framework.decorators import api_view
from rest_framework.request import Request
from rest_framework.response import Response

from core.problem_details import problem
from indicators.models import IndicatorObservation, ThreatIndicatorStatus, upsert_indicator
from submissions.models import ScamSubmission
from submissions.services import log_event

from .serializers import (
    CompleteSerializer,
    EnrichmentSerializer,
    OpenPhishIngestSerializer,
    StatusSerializer,
    WorkflowFailureSerializer,
)

logger = logging.getLogger(__name__)

_INTERNAL_DESC = (
    "Internal endpoint: requires the X-Internal-Service-Token header. "
    "Called only by n8n workflows — never exposed to end users."
)

# Providers whose MATCH counts as corroboration for indicator promotion (§5).
# A single user report never moves an indicator beyond REPORTED.
TRUSTED_CORROBORATORS = {"phishtank", "virustotal", "openphish"}


def _check_token(request: Request) -> bool:
    token = request.headers.get("X-Internal-Service-Token", "")
    expected = settings.INTERNAL_SERVICE_TOKEN
    if not expected:
        return False
    return hmac.compare_digest(token, expected)


def _promote_on_match(submission: ScamSubmission, indicator, provider: str) -> None:
    """Enforce + log indicator state transitions on trusted MATCH (§5).

    REPORTED --(first trusted MATCH)--> UNDER_REVIEW
    UNDER_REVIEW --(>=2 independent trusted MATCH providers)--> CORROBORATED
    Never CONFIRMED — that requires human review.
    """
    if provider not in TRUSTED_CORROBORATORS:
        return

    def _transition(new_status: str, *, trusted: bool) -> None:
        previous = indicator.status
        try:
            indicator.transition_to(new_status, trusted=trusted)
        except ValueError:
            return
        log_event(
            submission,
            "indicator_transition",
            summary={
                "indicator_type": indicator.indicator_type,
                "from": previous,
                "to": new_status,
                "provider": provider,
            },
        )

    if indicator.status == ThreatIndicatorStatus.REPORTED:
        _transition(ThreatIndicatorStatus.UNDER_REVIEW, trusted=False)

    if indicator.status == ThreatIndicatorStatus.UNDER_REVIEW:
        match_providers = set(
            indicator.observations.filter(outcome="MATCH")
            .values_list("provider", flat=True)
            .distinct()
        )
        trusted_matches = match_providers & TRUSTED_CORROBORATORS
        if len(trusted_matches) >= 2:
            _transition(ThreatIndicatorStatus.CORROBORATED, trusted=True)


@extend_schema(
    request=EnrichmentSerializer,
    responses={200: StatusSerializer},
    description=_INTERNAL_DESC,
    tags=["internal"],
)
@api_view(["POST"])
def enrichment(request: Request, scan_id: str) -> Response:
    """POST /internal/scans/{scan_id}/enrichment."""
    if not _check_token(request):
        return problem("Unauthorized", 401)
    try:
        submission = ScamSubmission.objects.get(id=scan_id)
    except (ScamSubmission.DoesNotExist, ValueError):
        return problem("Scan not found", 404)

    serializer = EnrichmentSerializer(data=request.data)
    if not serializer.is_valid():
        return problem("Validation failed", 400, str(serializer.errors))
    observations = serializer.validated_data["observations"]
    log_event(submission, "enrichment_received", summary={"count": len(observations)})

    from core.views import PROVIDER_OUTCOMES

    for obs in observations:
        from core.crypto import hmac_digest

        digest, _ = hmac_digest(obs["normalised_value"])
        provider = obs["provider"]
        outcome = obs["outcome"]
        indicator, _ = upsert_indicator(obs["type"], digest)
        IndicatorObservation.objects.create(
            indicator=indicator,
            provider=provider,
            outcome=outcome,
            response_reference=str(obs.get("response_reference", ""))[:500],
            error_detail=str(obs.get("error_detail", ""))[:500],
        )
        if PROVIDER_OUTCOMES is not None:
            PROVIDER_OUTCOMES.labels(provider=provider, outcome=outcome).inc()
        if outcome == "MATCH":
            _promote_on_match(submission, indicator, provider)

    return Response({"status": "recorded"})


@extend_schema(
    request=CompleteSerializer,
    responses={200: StatusSerializer},
    description=_INTERNAL_DESC,
    tags=["internal"],
)
@api_view(["POST"])
def complete(request: Request, scan_id: str) -> Response:
    """POST /internal/scans/{scan_id}/complete."""
    if not _check_token(request):
        return problem("Unauthorized", 401)
    try:
        submission = ScamSubmission.objects.get(id=scan_id)
    except (ScamSubmission.DoesNotExist, ValueError):
        return problem("Scan not found", 404)
    serializer = CompleteSerializer(data=request.data)
    if not serializer.is_valid():
        return problem("Validation failed", 400, str(serializer.errors))
    log_event(
        submission,
        "enrichment_done",
        summary={"status": serializer.validated_data["status"]},
    )
    from assessment.services import run_assessment

    # providers_ran must reflect THIS scan's enrichment arrival. Observations
    # are matched globally by (type, digest), so another scan's observations
    # for the same indicator must not mark this scan as "providers ran".
    enrichment_seen = submission.events.filter(event_type="enrichment_received").exists()
    # An empty observation set means no provider actually ran. Treat that as
    # inconclusive rather than "no known threat detected".
    run_assessment(str(scan_id), providers_ran=enrichment_seen)
    return Response({"status": "complete"})


@extend_schema(
    request=OpenPhishIngestSerializer,
    responses={200: OpenApiTypes.OBJECT},
    description=_INTERNAL_DESC,
    tags=["internal"],
)
@api_view(["POST"])
def openphish_ingest(request: Request) -> Response:
    """POST /internal/openphish/ingest — feed sync target for n8n (§8).

    Scheduled every 12h by the OpenPhish Feed Sync workflow. Stores digests +
    normalised URLs in a local table; never queried per user request.
    """
    if not _check_token(request):
        return problem("Unauthorized", 401)

    from core.crypto import hmac_digest
    from intel.models import OpenPhishEntry
    from submissions.normalisation import normalise_url

    serializer = OpenPhishIngestSerializer(data=request.data)
    if not serializer.is_valid():
        return problem("Invalid payload", 400, str(serializer.errors))
    urls = serializer.validated_data["urls"]

    pairs: list[tuple[bytes, str]] = []
    for raw in urls:
        if not isinstance(raw, str):
            continue
        normalised = normalise_url(raw)
        if not normalised:
            continue
        digest, _ = hmac_digest(normalised)
        pairs.append((digest, normalised))

    created = OpenPhishEntry.ingest_urls(pairs)
    logger.info("openphish_ingest", extra={"feed_urls": len(urls), "new_entries": created})
    return Response({"received": len(urls), "created": created})


@extend_schema(
    request=WorkflowFailureSerializer,
    responses={200: StatusSerializer},
    description=_INTERNAL_DESC,
    tags=["internal"],
)
@api_view(["POST"])
def workflow_failure(request: Request) -> Response:
    """POST /internal/workflow-failures — n8n Error Trigger target.

    Failure payloads can embed user content in ``error_message``, so only the
    execution metadata is written to the structured log. Operators use the
    execution id to inspect the failed run in n8n.
    """
    if not _check_token(request):
        return problem("Unauthorized", 401)

    serializer = WorkflowFailureSerializer(data=request.data)
    if not serializer.is_valid():
        return problem("Invalid payload", 400, str(serializer.errors))
    data = serializer.validated_data

    logger.warning(
        "n8n_workflow_failure",
        extra={
            "workflow_name": data["workflow_name"],
            "execution_id": data["execution_id"],
            "failed_node": data["failed_node"],
            "occurred_at": data["occurred_at"],
        },
    )
    return Response({"status": "recorded"})
