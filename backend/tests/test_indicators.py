"""Unit tests: indicator state transitions + concurrent upserts."""

import threading

import pytest

from core.crypto import hmac_digest
from indicators.models import ThreatIndicator, ThreatIndicatorStatus, upsert_indicator


@pytest.mark.django_db(transaction=True)
class TestStateTransitions:
    def test_reported_to_under_review(self):
        digest, _ = hmac_digest("https://evil.example/")
        ind, _ = upsert_indicator("URL", digest)
        ind.transition_to(ThreatIndicatorStatus.UNDER_REVIEW)
        assert ind.status == ThreatIndicatorStatus.UNDER_REVIEW

    def test_promotion_needs_trust(self):
        digest, _ = hmac_digest("https://evil2.example/")
        ind, _ = upsert_indicator("URL", digest)
        ind.transition_to(ThreatIndicatorStatus.UNDER_REVIEW)
        with pytest.raises(ValueError, match="trusted"):
            ind.transition_to(ThreatIndicatorStatus.CORROBORATED, trusted=False)
        ind.transition_to(ThreatIndicatorStatus.CORROBORATED, trusted=True)
        assert ind.status == ThreatIndicatorStatus.CORROBORATED

    def test_illegal_jump(self):
        digest, _ = hmac_digest("https://evil3.example/")
        ind, _ = upsert_indicator("URL", digest)
        with pytest.raises(ValueError):
            ind.transition_to(ThreatIndicatorStatus.CONFIRMED)

    def test_single_report_only_reported(self):
        digest, _ = hmac_digest("https://evil4.example/")
        ind, created = upsert_indicator("URL", digest)
        assert created
        assert ind.status == ThreatIndicatorStatus.REPORTED


@pytest.mark.django_db
class TestPairLookup:
    def test_only_exact_type_digest_pairs_match(self):
        from indicators.models import threat_indicators_for

        digest, _ = hmac_digest("shared-value.example")
        upsert_indicator("DOMAIN", digest)
        upsert_indicator("EMAIL", digest)

        rows = threat_indicators_for({("DOMAIN", digest)})
        assert list(rows.values_list("indicator_type", flat=True)) == ["DOMAIN"]

    def test_empty_pairs_match_nothing(self):
        from indicators.models import threat_indicators_for

        assert not threat_indicators_for(set()).exists()


@pytest.mark.django_db(transaction=True)
class TestConcurrentUpsert:
    def test_parallel_upserts_safe(self):
        # SQLite serialises writers; retry-on-lock mirrors Postgres behaviour
        import time

        from django.db import OperationalError, connection

        digest, _ = hmac_digest("https://evil5.example/")
        errors: list[Exception] = []

        def worker():
            for _ in range(5):
                try:
                    connection.close()
                    upsert_indicator("URL", digest)
                    return
                except OperationalError as exc:
                    if "locked" not in str(exc).lower():
                        errors.append(exc)
                        return
                    time.sleep(0.05)
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)
                    return

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        assert ThreatIndicator.objects.filter(indicator_type="URL", digest=digest).count() == 1
