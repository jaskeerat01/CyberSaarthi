"""API contract tests."""

import pytest
from django.test import Client
from rest_framework.test import APIClient


@pytest.mark.django_db
class TestScansAPI:
    def test_create_scan_202(self):
        client = APIClient()
        resp = client.post(
            "/api/v1/scans",
            {"raw_content": "Check https://evil.example/login now", "reported_financial_loss": False},
            format="json",
        )
        assert resp.status_code == 202
        assert "scan_id" in resp.data

    def test_create_scan_1930_flag(self):
        client = APIClient()
        resp = client.post(
            "/api/v1/scans",
            {"raw_content": "I lost money on https://x.example", "reported_financial_loss": True},
            format="json",
        )
        assert resp.status_code == 202
        assert resp.data["reported_financial_loss"] is True

    def test_idempotency(self):
        client = APIClient()
        payload = {"raw_content": "Same content https://dup.example"}
        r1 = client.post("/api/v1/scans", payload, format="json")
        r2 = client.post("/api/v1/scans", payload, format="json")
        assert r1.data["scan_id"] == r2.data["scan_id"]

    def test_get_scan(self):
        client = APIClient()
        r = client.post("/api/v1/scans", {"raw_content": "hello https://a.example"}, format="json")
        scan_id = r.data["scan_id"]
        resp = client.get(f"/api/v1/scans/{scan_id}")
        assert resp.status_code == 200
        assert resp.data["scan_id"] == scan_id

    def test_delete_scan(self):
        client = APIClient()
        r = client.post("/api/v1/scans", {"raw_content": "delete me https://d.example"}, format="json")
        scan_id = r.data["scan_id"]
        resp = client.delete(f"/api/v1/scans/{scan_id}")  # spec path §6
        assert resp.status_code == 204
        assert client.get(f"/api/v1/scans/{scan_id}").status_code == 404

    def test_idempotency_key_header(self):
        client = APIClient()
        key = "test-idem-key-123"
        payload = {"raw_content": "unique content https://idem.example"}
        r1 = client.post("/api/v1/scans", payload, format="json", HTTP_IDEMPOTENCY_KEY=key)
        # Different content, same Idempotency-Key → same scan returned
        r2 = client.post(
            "/api/v1/scans", {"raw_content": "different"}, format="json", HTTP_IDEMPOTENCY_KEY=key
        )
        assert r1.data["scan_id"] == r2.data["scan_id"]

    def test_submission_throttle_engages(self):
        from django.core.cache import cache

        cache.clear()
        client = APIClient()
        codes = []
        for i in range(32):
            resp = client.post(
                "/api/v1/scans", {"raw_content": f"throttle probe {i}"}, format="json"
            )
            codes.append(resp.status_code)
        # Default submissions rate is 30/hour — 31st+ request throttled
        assert 429 in codes
        cache.clear()

    def test_validation_error_problem_details(self):
        client = APIClient()
        resp = client.post("/api/v1/scans", {"raw_content": "x" * 6000}, format="json")
        assert resp.status_code in (400, 413)

    def test_never_says_safe(self):
        client = APIClient()
        r = client.post("/api/v1/scans", {"raw_content": "clean text here"}, format="json")
        scan_id = r.data["scan_id"]
        resp = client.get(f"/api/v1/scans/{scan_id}")
        if resp.data.get("classification"):
            assert resp.data["classification"] != "SAFE"
            assert "safe" not in str(resp.data).lower() or "disclaimer" in resp.data


@pytest.mark.django_db
class TestInternalAPI:
    def test_internal_requires_token(self):
        from submissions.services import create_submission

        sub = create_submission("https://internal.example/test")
        client = APIClient()
        resp = client.post(
            f"/internal/scans/{sub.id}/enrichment",
            {"observations": []},
            format="json",
        )
        assert resp.status_code == 401

    def test_internal_enrichment_with_token(self):
        from submissions.services import create_submission

        sub = create_submission("https://internal2.example/test")
        client = APIClient()
        resp = client.post(
            f"/internal/scans/{sub.id}/enrichment",
            {"observations": []},
            format="json",
            HTTP_X_INTERNAL_SERVICE_TOKEN="test-internal-token",
        )
        assert resp.status_code == 200


@pytest.mark.django_db
class TestHealth:
    def test_healthz(self):
        assert Client().get("/healthz").status_code == 200

    def test_readyz(self):
        resp = Client().get("/readyz")
        assert resp.status_code in (200, 503)  # 503 if redis down in test env

    def test_openapi(self):
        resp = Client().get("/api/schema/")
        assert resp.status_code == 200
        assert b"openapi" in resp.content
