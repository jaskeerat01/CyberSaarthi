"""PDF generation with WeasyPrint (ADR 0001). On-demand, served via signed URL."""

from __future__ import annotations

import html
import logging

from django.core.signing import BadSignature

from submissions.models import ScamSubmission

logger = logging.getLogger(__name__)


def _defang(text: str) -> str:
    """Defang URLs for display: hxxps://example[.]com"""
    return html.escape(text.replace("http", "hxxp").replace(".", "[.]", 2))


def generate_pdf(scan_id: str) -> bytes:
    """Generate 'Cyber Fraud Evidence and Complaint Preparation Report'."""
    from weasyprint import HTML

    submission = ScamSubmission.objects.get(id=scan_id)
    assessment = getattr(submission, "assessment", None)
    indicators = submission.indicators.all()

    # Per-provider outcomes + RDAP registration info (spec §13)
    from indicators.models import IndicatorObservation, ThreatIndicator

    type_digests = {(i.indicator_type, bytes(i.digest)) for i in indicators}
    threat_rows = ThreatIndicator.objects.filter(
        indicator_type__in=[t for t, _ in type_digests],
        digest__in=[d for _, d in type_digests],
    )
    provider_rows = IndicatorObservation.objects.filter(indicator__in=threat_rows)
    provider_html = "\n".join(
        f"<tr><td>{html.escape(o.provider)}</td><td>{html.escape(o.outcome)}</td>"
        f"<td>{html.escape(o.response_reference or '—')}</td></tr>"
        for o in provider_rows
    ) or "<tr><td colspan='3'>No provider observations recorded</td></tr>"
    rdap_reg = next(
        (o.response_reference for o in provider_rows if o.provider == "rdap" and o.response_reference),
        None,
    )
    analysis_ts = assessment.created_at.isoformat() if assessment else "—"

    url_list = "\n".join(
        f"<li>{_defang(ind.normalised_value)}</li>"
        for ind in indicators
        if ind.indicator_type in ("URL", "DOMAIN")
    )
    evidence_html = ""
    if assessment:
        evidence_html = f"""
        <h2>Classification</h2>
        <p><strong>{html.escape(assessment.classification)}</strong> (confidence: {html.escape(assessment.confidence)})</p>
        <p>Rule IDs: {html.escape(', '.join(assessment.rule_ids))} — ruleset {html.escape(assessment.ruleset_version)}</p>
        <h2>Technical evidence</h2>
        <pre>{html.escape(str(assessment.technical_evidence))}</pre>
        <h2>Social-engineering evidence</h2>
        <pre>{html.escape(str(assessment.social_engineering_evidence))}</pre>
        """

    provider_html_full = f"""
    <h2>Per-provider threat-intelligence outcomes</h2>
    <table border="1" cellpadding="4" cellspacing="0">
      <tr><th>Provider</th><th>Outcome</th><th>Reference / registration date</th></tr>
      {provider_html}
    </table>
    <p>Domain registration (RDAP): {html.escape(rdap_reg) if rdap_reg else 'not available'}</p>
    <p>Analysis timestamp: {html.escape(analysis_ts)}</p>
    """

    body = f"""
    <html lang="en"><head><meta charset="utf-8">
    <style>body {{ font-family: sans-serif; margin: 2em; }} h1 {{ border-bottom: 2px solid #333; }}</style>
    </head><body>
    <h1>Cyber Fraud Evidence and Complaint Preparation Report</h1>
    <p><em>This is not a submitted complaint. No authority has accepted this document.
    It helps you prepare a complaint on the official portal: cybercrime.gov.in</em></p>
    <h2>Original submission</h2>
    <pre>{html.escape(submission.raw_content)}</pre>
    <h2>Extracted identifiers</h2>
    <ul>{url_list}</ul>
    <p>Submitted: {submission.created_at.isoformat()}<br>
    Retention expires: {submission.retention_expires_at.isoformat() if submission.retention_expires_at else '—'}</p>
    {evidence_html}
    {provider_html_full}
    <h2>Incident description (complete this section before filing)</h2>
    <p>Describe what happened, when, and how you were contacted:</p>
    <p>____________________________________________________________</p>
    <p>____________________________________________________________</p>
    <p>____________________________________________________________</p>
    <h2>If you lost money</h2>
    <p><strong>Call the National Cyber Crime Helpline: 1930</strong></p>
    <h2>Checklist to gather</h2>
    <ul>
      <li>Screenshots (with metadata — originals preserved separately)</li>
      <li>Transaction IDs, dates, amounts</li>
      <li>Phone numbers / UPI IDs involved</li>
      <li>Any messages received</li>
    </ul>
    <h2>Official reporting</h2>
    <p>File a complaint at cybercrime.gov.in. Helpline: 1930.</p>
    </body></html>
    """
    return HTML(string=body).write_pdf()


def signed_url(scan_id: str, max_age: int = 900) -> dict:
    """Short-lived signed URL for PDF download."""
    from urllib.parse import quote

    from django.core.signing import TimestampSigner

    signer = TimestampSigner(salt="report")
    token = signer.sign_object({"scan_id": str(scan_id)})
    scan_id = str(scan_id)
    return {
        "url": f"/api/v1/scans/{scan_id}/report.pdf?token={quote(token)}",
        "expires_in": max_age,
    }


def verify_token(token: str, scan_id: str, max_age: int = 900) -> bool:
    """Verify signed token for a scan."""
    from django.core.signing import TimestampSigner

    try:
        signer = TimestampSigner(salt="report")
        data = signer.unsign_object(token, max_age=max_age)
        return str(data.get("scan_id")) == str(scan_id)
    except BadSignature:
        return False
