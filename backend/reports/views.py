"""Report PDF endpoint — on demand, served via a short-lived signed URL."""

from __future__ import annotations

from django.http import HttpResponse
from drf_spectacular.utils import OpenApiParameter, OpenApiTypes, extend_schema
from rest_framework.decorators import api_view, throttle_classes
from rest_framework.request import Request
from rest_framework.response import Response

from core.problem_details import problem
from core.throttles import ReportRateThrottle
from submissions.models import ScamSubmission

from .pdf import generate_pdf, signed_url, verify_token


@extend_schema(
    auth=[],
    parameters=[
        OpenApiParameter(
            name="token",
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            required=False,
            description="Signed token minted by a tokenless request (valid 15 minutes).",
        )
    ],
    responses={200: OpenApiTypes.OBJECT},
    description=(
        "Two-step download (spec §6): without ?token returns 200 JSON "
        "`{url, expires_in}` with a short-lived signed URL; with a valid token "
        "returns the generated report as application/pdf."
    ),
)
@api_view(["GET"])
@throttle_classes([ReportRateThrottle])
def report_pdf(request: Request, scan_id: str) -> Response | HttpResponse:
    """GET /api/v1/scans/{scan_id}/report.pdf

    Without a token: mints a short-lived signed URL (spec §6).
    With a valid token: serves the generated PDF.
    """
    try:
        ScamSubmission.objects.get(id=scan_id)
    except ScamSubmission.DoesNotExist:
        return problem("Scan not found", 404)
    except ValueError:
        return problem("Scan not found", 404)

    token = request.query_params.get("token", "")
    if not token:
        return Response(signed_url(scan_id))

    if not verify_token(token, scan_id):
        return problem("Invalid or expired token", 403)
    pdf_bytes = generate_pdf(scan_id)
    return HttpResponse(pdf_bytes, content_type="application/pdf")
