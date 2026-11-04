"""Fast-path tests (§7): verified MATCH resolves; NO_MATCH always slow-path."""

import pytest
from django.core.cache import cache

from indicators.models import upsert_indicator
from intel.fastpath import fast_path_check
from submissions.services import create_submission


@pytest.mark.django_db
class TestFastPath:
    def setup_method(self):
        cache.clear()

    def teardown_method(self):
        cache.clear()

    def test_no_indicators_goes_slow_path(self):
        sub = create_submission("no links at all here")
        assert fast_path_check(sub) is None

    def test_unverified_indicator_goes_slow_path(self):
        sub = create_submission("see https://unknown.example/login")
        # Nothing in threat_indicators → unresolved → slow path
        assert fast_path_check(sub) is None

    def test_no_match_cache_does_not_skip_slow_path(self):
        """Regression: cached NO_MATCH must still fall through to n8n (R2)."""
        sub = create_submission("visit https://cachemiss.example/x")
        # Seed cache exactly as a prior run would (NO_MATCH for URL indicator)
        url_ind = sub.indicators.get(indicator_type="URL")
        cache.set(f"ti:URL:{bytes(url_ind.digest).hex()[:32]}", "NO_MATCH", timeout=300)
        assert fast_path_check(sub) is None  # must NOT resolve on cached NO_MATCH

    def test_verified_match_resolves(self):
        sub = create_submission("check https://known-bad.example/here")
        # Confirm every extracted indicator (URL + DOMAIN)
        for url_ind in sub.indicators.all():
            ind, _ = upsert_indicator(url_ind.indicator_type, bytes(url_ind.digest))
            ind.status = "CONFIRMED"
            ind.save(update_fields=["status"])
        cache.clear()  # ensure DB path (first call) resolves
        result = fast_path_check(sub)
        assert result is not None
        assert all(o["outcome"] == "MATCH" for o in result)
        # Second call: served from cache
        assert fast_path_check(sub) is not None

    def test_reported_status_does_not_resolve(self):
        """REPORTED (single user report) is never a fast-path verified hit."""
        sub = create_submission("open https://reported-only.example/")
        url_ind = sub.indicators.get(indicator_type="URL")
        ind, _ = upsert_indicator("URL", bytes(url_ind.digest))
        assert ind.status == "REPORTED"
        cache.clear()
        assert fast_path_check(sub) is None
