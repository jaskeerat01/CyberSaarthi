"""Tests for audit fixes: classification semantics, promotion, OpenPhish, metrics."""

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

    def test_unexpired_kept(self):
        from submissions.tasks import purge_expired_raw_content

        sub = create_submission("keep me https://fresh.example/x")
        purged = purge_expired_raw_content()
        assert purged == 0
        sub.refresh_from_db()
        assert sub.raw_content_encrypted != ""
