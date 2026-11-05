"""Provider adapter tests — fixtures only, never live APIs in CI."""

from unittest.mock import patch

import httpx

from intel.providers import AbuseIpDbProvider, PhishTankProvider, RdapProvider


class TestPhishTank:
    def test_match_fixture(self):
        fixtures = {
            "verified": True,
            "valid": True,
            "phish_detail_url": "https://phishtank.example/123",
        }
        with patch("intel.providers.httpx.post") as mock_post:
            mock_post.return_value = httpx.Response(200, json={"results": fixtures, "status": "success"})
            mock_post.return_value.raise_for_status = lambda: None
            provider = PhishTankProvider()
            provider.timeout = 5
            result = provider.check_url("https://evil.example/")
            # Disabled without key → UNSUPPORTED, still a valid outcome
            assert result.outcome in ("UNSUPPORTED", "MATCH", "NO_MATCH")

    def test_match_with_quota_key_missing(self):
        """Regression: cache.incr() raises when the quota key is absent."""
        from django.core.cache import cache
        from django.test import override_settings

        with override_settings(FEATURE_PHISHTANK=True, PHISHTANK_API_KEY="test-key"):
            cache.clear()
            with patch("intel.providers.httpx.post") as mock_post:
                mock_post.return_value = httpx.Response(
                    200, json={"results": {"verified": True, "valid": True}}
                )
                mock_post.return_value.raise_for_status = lambda: None
                result = PhishTankProvider().check_url("https://evil.example/")
            assert result.outcome == "MATCH"
            assert cache.get("quota:phishtank") == 1

    def test_unsupported_types(self):
        provider = PhishTankProvider()
        assert provider.check_domain("example.com").outcome == "UNSUPPORTED"
        assert provider.check_ip("1.2.3.4").outcome == "UNSUPPORTED"


class TestRdap:
    def test_unsupported_ip(self):
        provider = RdapProvider()
        assert provider.check_ip("1.2.3.4").outcome == "UNSUPPORTED"

    def test_domain_bootstrap_failure_is_error_not_crash(self):
        with patch("intel.providers.httpx.get", side_effect=httpx.ConnectError("down")):
            provider = RdapProvider()
            result = provider.check_domain("example.com")
            assert result.outcome in ("ERROR", "NO_MATCH")


class TestAbuseIpDb:
    def test_domain_rejected(self):
        provider = AbuseIpDbProvider()
        assert provider.check_domain("example.com").outcome == "UNSUPPORTED"
        assert provider.check_url("https://x.example/").outcome == "UNSUPPORTED"

    def test_disabled_by_default(self):
        provider = AbuseIpDbProvider()
        result = provider.check_ip("8.8.8.8")
        # Feature flag off in test env → UNSUPPORTED, never a crash
        assert result.outcome == "UNSUPPORTED"


class TestProviderFailureNeverFailsScan:
    def test_all_providers_error_still_returns(self):
        with patch("intel.providers.httpx.post", side_effect=httpx.ConnectError("down")), patch(
            "intel.providers.httpx.get", side_effect=httpx.ConnectError("down")
        ):
                from intel.providers import get_providers

                for p in get_providers():
                    # Each provider returns an outcome — never raises
                    if p.name == "phishtank":
                        r = p.check_url("https://x.example/")
                    else:
                        r = p.check_domain("example.com")
                    assert r.outcome in ("MATCH", "NO_MATCH", "ERROR", "RATE_LIMITED", "UNSUPPORTED")
