"""Tests for audit fixes: classification semantics, promotion, OpenPhish, metrics."""

from datetime import UTC

import pytest
from rest_framework.test import APIClient

from assessment.services import build_assessment
from submissions.services import create_submission


@pytest.mark.django_db
class TestClassificationSemantics:
    def test_abuseipdb_match_alone_does_not_confirm(self):
        """§1: CONFIRMED_MALICIOUS requires reliable, verified TI."""
        sub = create_submission("plain text with no links")
        payload = build_assessment(
            sub, [{"provider": "abuseipdb", "outcome": "MATCH"}]
        )
        assert payload["classification"] != "CONFIRMED_MALICIOUS"

    def test_phishtank_match_confirms(self):
        sub = create_submission("plain text with no links")
        payload = build_assessment(sub, [{"provider": "phishtank", "outcome": "MATCH"}])
        assert payload["classification"] == "CONFIRMED_MALICIOUS"
        assert payload["confidence"] == "HIGH"

    def test_abuseipdb_plus_se_is_high_risk(self):
        sub = create_submission("Act now! Verify your OTP immediately.")
        payload = build_assessment(
            sub,
            [
                {"provider": "abuseipdb", "outcome": "MATCH"},
                {"provider": "rdap", "outcome": "ERROR"},
            ],
        )
        # technical MATCH + social_engineering → 2 categories → HIGH_RISK
        assert payload["classification"] == "HIGH_RISK"

    def test_provider_unavailable_no_signals_inconclusive(self):
        sub = create_submission("nothing special here")
        payload = build_assessment(
            sub, [{"provider": "phishtank", "outcome": "ERROR"}], providers_ran=True
        )
        assert payload["classification"] == "INCONCLUSIVE"

    def test_providers_never_ran_inconclusive(self):
        """No webhook → providers_ran=False → INCONCLUSIVE, never NO_KNOWN."""
        sub = create_submission("nothing special here either")
        payload = build_assessment(sub, [], providers_ran=False)
        assert payload["classification"] == "INCONCLUSIVE"

    def test_benign_url_with_clean_providers_is_no_known_threat(self):
        """A URL alone is structural, not a signal: cleared providers → NO_KNOWN."""
        sub = create_submission("check this link https://www.google.com/search?q=cats")
        payload = build_assessment(
            sub,
            [
                {"provider": "phishtank", "outcome": "NO_MATCH"},
                {"provider": "rdap", "outcome": "NO_MATCH"},
            ],
        )
        assert payload["classification"] == "NO_KNOWN_THREAT_DETECTED"

    def test_abuseipdb_match_alone_is_suspicious(self):
        """A single non-reliable MATCH is one weak technical signal → SUSPICIOUS."""
        sub = create_submission("ping 1.2.3.4 please")
        payload = build_assessment(sub, [{"provider": "abuseipdb", "outcome": "MATCH"}])
        assert payload["classification"] == "SUSPICIOUS"

    def test_rdap_new_domain_is_weak_signal(self):
        """RDAP registration <30d is a weak technical signal → SUSPICIOUS."""
        from datetime import datetime, timedelta

        sub = create_submission("see https://brand-new.example/login")
        recent = (datetime.now(UTC) - timedelta(days=5)).isoformat()
        payload = build_assessment(
            sub, [{"provider": "rdap", "outcome": "NO_MATCH", "response_reference": recent}]
        )
        assert "TECH_NEW_DOMAIN" in payload["rule_ids"]
        assert payload["classification"] == "SUSPICIOUS"

    def test_rdap_old_domain_is_not_a_signal(self):
        from datetime import datetime, timedelta

        sub = create_submission("see https://old-established.example/login")
        old = (datetime.now(UTC) - timedelta(days=400)).isoformat()
        payload = build_assessment(
            sub,
            [
                {"provider": "phishtank", "outcome": "NO_MATCH"},
                {"provider": "rdap", "outcome": "NO_MATCH", "response_reference": old},
            ],
        )
        assert "TECH_NEW_DOMAIN" not in payload["rule_ids"]
        assert payload["classification"] == "NO_KNOWN_THREAT_DETECTED"

    def test_rdap_malformed_date_is_ignored(self):
        sub = create_submission("see https://odd.example/login")
        payload = build_assessment(
            sub,
            [
                {"provider": "phishtank", "outcome": "NO_MATCH"},
                {"provider": "rdap", "outcome": "NO_MATCH", "response_reference": "not-a-date"},
            ],
        )
        assert "TECH_NEW_DOMAIN" not in payload["rule_ids"]
        assert payload["classification"] == "NO_KNOWN_THREAT_DETECTED"

    def test_account_suspension_rule_en(self):
        sub = create_submission("Your account suspended. Reactivate your account now.")
        payload = build_assessment(sub, [])
        assert "SE_ACCOUNT_SUSPENSION_EN" in payload["rule_ids"]

    def test_account_suspension_rule_hi(self):
        sub = create_submission("आपका खाता निलंबित कर दिया गया है")
        payload = build_assessment(sub, [])
        assert "SE_ACCOUNT_SUSPENSION_HI" in payload["rule_ids"]


@pytest.mark.django_db
class TestOpenPhishIngest:
    def test_ingest_requires_token(self):
        resp = APIClient().post("/internal/openphish/ingest", {"urls": []}, format="json")
        assert resp.status_code == 401

    def test_ingest_and_match(self):
        client = APIClient()
        resp = client.post(
            "/internal/openphish/ingest",
            {"urls": ["https://openphish-bad.example/login"]},
            format="json",
            HTTP_X_INTERNAL_SERVICE_TOKEN="test-internal-token",
        )
        assert resp.status_code == 200
        assert resp.data["created"] == 1

        # Re-ingest is idempotent
        resp2 = client.post(
            "/internal/openphish/ingest",
            {"urls": ["https://openphish-bad.example/login"]},
            format="json",
            HTTP_X_INTERNAL_SERVICE_TOKEN="test-internal-token",
        )
        assert resp2.data["created"] == 0

        # A submission containing that URL gets an openphish MATCH
        sub = create_submission("click https://openphish-bad.example/login now")
        from assessment.services import run_assessment

        assessment = run_assessment(str(sub.id))
        assert assessment.classification == "CONFIRMED_MALICIOUS"

    def test_ingest_rejects_malformed_payload(self):
        resp = APIClient().post(
            "/internal/openphish/ingest",
            {"urls": "not-a-list"},
            format="json",
            HTTP_X_INTERNAL_SERVICE_TOKEN="test-internal-token",
        )
        assert resp.status_code == 400

    def test_ingest_bulk_dedupes_within_batch(self):
        """Duplicate feed lines count once, and re-ingest refreshes last_seen."""
        from django.utils import timezone

        from core.crypto import hmac_digest
        from intel.models import OpenPhishEntry

        url = "https://bulk-openphish.example/login"
        digest, _ = hmac_digest(url)
        before = timezone.now() - timezone.timedelta(days=1)
        OpenPhishEntry.objects.filter(digest=digest).update(last_seen=before)

        resp = APIClient().post(
            "/internal/openphish/ingest",
            {"urls": [url, url, url]},
            format="json",
            HTTP_X_INTERNAL_SERVICE_TOKEN="test-internal-token",
        )
        assert resp.status_code == 200
        assert resp.data["received"] == 3
        # One created from the three identical lines.
        assert resp.data["created"] == 1
        assert OpenPhishEntry.objects.filter(digest=digest).count() == 1
        # Re-syncing an existing entry refreshes last_seen without duplicating.
        OpenPhishEntry.objects.filter(digest=digest).update(last_seen=before)
        resp2 = APIClient().post(
            "/internal/openphish/ingest",
            {"urls": [url]},
            format="json",
            HTTP_X_INTERNAL_SERVICE_TOKEN="test-internal-token",
        )
        assert resp2.data["created"] == 0
        entry = OpenPhishEntry.objects.get(digest=digest)
        assert entry.last_seen > before


@pytest.mark.django_db
class TestSubmissionLimits:
    def test_dense_submission_is_capped_to_workflow_contract(self):
        text = " ".join(f"https://site{i}.example/path" for i in range(60))
        sub = create_submission(text)
        assert sub.indicators.count() == 50

    def test_task_without_indicators_completes_without_calling_n8n(self):
        from unittest.mock import patch

        from config.celery import investigate_scan

        sub = create_submission("plain text without any link or number")
        with patch("intel.n8n_client.invoke_investigation") as mock_invoke:
            assert investigate_scan.apply(args=[str(sub.id)]).get() is False
        mock_invoke.assert_not_called()
        sub.refresh_from_db()
        assert sub.status == "COMPLETED"


@pytest.mark.django_db
class TestCompletionSemantics:
    def test_complete_without_observations_is_inconclusive(self):
        sub = create_submission("call +91 98765 43210")
        resp = APIClient().post(
            f"/internal/scans/{sub.id}/complete",
            {"status": "enrichment_done"},
            format="json",
            HTTP_X_INTERNAL_SERVICE_TOKEN="test-internal-token",
        )
        assert resp.status_code == 200
        sub.refresh_from_db()
        assert sub.status == "COMPLETED"
        assert sub.assessment.classification == "INCONCLUSIVE"


@pytest.mark.django_db
class TestScanTaskStatus:
    def test_task_marks_scan_running_before_webhook(self):
        from unittest.mock import patch

        from config.celery import investigate_scan

        sub = create_submission("check https://task.example/path")
        with patch("intel.n8n_client.invoke_investigation", return_value=True):
            assert investigate_scan.apply(args=[str(sub.id)]).get() is True
        sub.refresh_from_db()
        assert sub.status == "RUNNING"
        assert sub.events.filter(event_type="slow_path_started").exists()


@pytest.mark.django_db
class TestWorkflowFailure:
    endpoint = "/internal/workflow-failures"

    def test_requires_token(self):
        resp = APIClient().post(self.endpoint, {}, format="json")
        assert resp.status_code == 401

    def test_records_valid_failure(self):
        resp = APIClient().post(
            self.endpoint,
            {
                "workflow_name": "CyberSathi - Scan Investigation",
                "execution_id": "42",
                "failed_node": "Post Enrichment to API",
                "error_message": "connection refused",
                "occurred_at": "2026-11-05T10:00:00Z",
            },
            format="json",
            HTTP_X_INTERNAL_SERVICE_TOKEN="test-internal-token",
        )
        assert resp.status_code == 200
        assert resp.data["status"] == "recorded"

    def test_rejects_malformed_payload(self):
        resp = APIClient().post(
            self.endpoint,
            {"workflow_name": "", "execution_id": ""},
            format="json",
            HTTP_X_INTERNAL_SERVICE_TOKEN="test-internal-token",
        )
        assert resp.status_code == 400


@pytest.mark.django_db
class TestIndicatorPromotion:
    def _post_enrichment(self, scan_id: str, observations: list):
        return APIClient().post(
            f"/internal/scans/{scan_id}/enrichment",
            {"observations": observations},
            format="json",
            HTTP_X_INTERNAL_SERVICE_TOKEN="test-internal-token",
        )

    def test_single_match_only_under_review(self):
        sub = create_submission("check https://promo1.example/please")
        value = "https://promo1.example/please"
        resp = self._post_enrichment(
            str(sub.id),
            [{"type": "URL", "normalised_value": value, "provider": "phishtank", "outcome": "MATCH"}],
        )
        assert resp.status_code == 200
        from core.crypto import hmac_digest
        from indicators.models import ThreatIndicator

        digest, _ = hmac_digest(value)
        ind = ThreatIndicator.objects.get(indicator_type="URL", digest=digest)
        assert ind.status == "UNDER_REVIEW"  # never CONFIRMED by single provider
        # Transition logged in workflow_events (§5)
        assert sub.events.filter(event_type="indicator_transition").exists()

    def test_two_trusted_matches_corroborate(self):
        sub = create_submission("check https://promo2.example/please")
        value = "https://promo2.example/please"
        for provider in ("phishtank", "openphish"):
            self._post_enrichment(
                str(sub.id),
                [{"type": "URL", "normalised_value": value, "provider": provider, "outcome": "MATCH"}],
            )
        from core.crypto import hmac_digest
        from indicators.models import ThreatIndicator

        digest, _ = hmac_digest(value)
        ind = ThreatIndicator.objects.get(indicator_type="URL", digest=digest)
        assert ind.status == "CORROBORATED"

    def test_legacy_indicator_field_names_are_accepted(self):
        """Older n8n exports send indicator_type/indicator_value."""
        sub = create_submission("check https://promo4.example/please")
        value = "https://promo4.example/please"
        resp = APIClient().post(
            f"/internal/scans/{sub.id}/enrichment",
            {
                "observations": [
                    {
                        "indicator_type": "URL",
                        "indicator_value": value,
                        "provider": "phishtank",
                        "outcome": "MATCH",
                    }
                ]
            },
            format="json",
            HTTP_X_INTERNAL_SERVICE_TOKEN="test-internal-token",
        )
        assert resp.status_code == 200
        from core.crypto import hmac_digest
        from indicators.models import ThreatIndicator

        digest, _ = hmac_digest(value)
        ind = ThreatIndicator.objects.get(indicator_type="URL", digest=digest)
        assert ind.status == "UNDER_REVIEW"

    def test_abuseipdb_match_does_not_promote(self):
        sub = create_submission("check https://promo3.example/please")
        value = "https://promo3.example/please"
        self._post_enrichment(
            str(sub.id),
            [{"type": "URL", "normalised_value": value, "provider": "abuseipdb", "outcome": "MATCH"}],
        )
        from core.crypto import hmac_digest
        from indicators.models import ThreatIndicator

        digest, _ = hmac_digest(value)
        ind = ThreatIndicator.objects.get(indicator_type="URL", digest=digest)
        assert ind.status == "REPORTED"


@pytest.mark.django_db
class TestMetrics:
    def test_metrics_endpoint(self):
        from django.core.cache import cache

        cache.clear()
        # Warm a request so latency histogram has a sample
        APIClient().get("/healthz")
        resp = APIClient().get("/metrics")
        assert resp.status_code == 200
        assert b"cybersathi_request_latency_seconds" in resp.content


@pytest.mark.django_db
class TestRetentionPurge:
    def test_expired_content_purged(self):
        from django.utils import timezone

        from submissions.models import ScamSubmission
        from submissions.tasks import purge_expired_raw_content

        sub = create_submission("expire me https://old.example/x")
        ScamSubmission.objects.filter(id=sub.id).update(
            retention_expires_at=timezone.now() - timezone.timedelta(days=1)
        )
        purged = purge_expired_raw_content()
        assert purged == 1
        sub.refresh_from_db()
        assert sub.raw_content_encrypted == ""  # raw content gone, row survives
        assert sub.raw_content == ""  # decrypting purged content must not crash
        # Extracted PII is purged with the raw content; digests remain.
        assert all(ind.normalised_value == "" for ind in sub.indicators.all())

    def test_unexpired_kept(self):
        from submissions.tasks import purge_expired_raw_content

        sub = create_submission("keep me https://fresh.example/x")
        purged = purge_expired_raw_content()
        assert purged == 0
        sub.refresh_from_db()
        assert sub.raw_content_encrypted != ""
