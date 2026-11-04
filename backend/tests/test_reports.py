"""Report + security tests."""

import pytest
from rest_framework.test import APIClient


@pytest.mark.django_db
class TestReport:
    def test_signed_url_minted_without_token(self):
        client = APIClient()
        r = client.post("/api/v1/scans", {"raw_content": "https://report.example/x"}, format="json")
        scan_id = r.data["scan_id"]
        # No token → short-lived signed URL issued (spec §6)
        resp = client.get(f"/api/v1/scans/{scan_id}/report.pdf")
        assert resp.status_code == 200
        assert "url" in resp.data and "token=" in resp.data["url"]
        assert resp.data["expires_in"] == 900

    def test_report_with_valid_token(self):
        from urllib.parse import unquote

        from reports.pdf import signed_url

        client = APIClient()
        r = client.post("/api/v1/scans", {"raw_content": "https://report2.example/x"}, format="json")
        scan_id = r.data["scan_id"]
        url = signed_url(scan_id)["url"]
        token = unquote(url.split("token=")[-1])
        resp = client.get(f"/api/v1/scans/{scan_id}/report.pdf?token={token}")
        assert resp.status_code == 200
        assert resp["Content-Type"] == "application/pdf"

    def test_report_rejects_tampered_token(self):
        client = APIClient()
        r = client.post("/api/v1/scans", {"raw_content": "https://report3.example/x"}, format="json")
        scan_id = r.data["scan_id"]
        resp = client.get(f"/api/v1/scans/{scan_id}/report.pdf?token=forged")
        assert resp.status_code == 403


@pytest.mark.django_db
class TestSecurityHeaders:
    def test_csp_present(self):
        client = APIClient()
        resp = client.get("/healthz")
        assert "Content-Security-Policy" in resp
        assert "script-src 'self'" in resp["Content-Security-Policy"]


@pytest.mark.django_db
class TestTelegram:
    def test_dedupe_and_secret(self):
        client = APIClient()
        payload = {"update_id": 12345, "message": {"text": "suspicious https://tg.example"}}
        r1 = client.post("/api/v1/telegram/webhook", payload, format="json")
        assert r1.status_code == 202
        r2 = client.post("/api/v1/telegram/webhook", payload, format="json")
        assert r2.data.get("status") == "duplicate"
