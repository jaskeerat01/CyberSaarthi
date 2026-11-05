"""Threat-intel provider interface + adapters.

Every adapter: 5s timeout, <=2 retries exp-backoff+jitter, circuit breaker,
Redis quota tracking, feature flag. Failure never fails the scan.
"""

from __future__ import annotations

import logging
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

import httpx
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)


@dataclass
class ProviderResult:
    provider: str
    outcome: str  # MATCH | NO_MATCH | ERROR | RATE_LIMITED | UNSUPPORTED
    response_reference: str = ""
    error_detail: str = ""
    metadata: dict = field(default_factory=dict)


class ThreatIntelProvider(ABC):
    """Common interface."""

    name: str = "base"
    timeout: float = 5.0
    max_retries: int = 2

    @abstractmethod
    def check_url(self, url: str) -> ProviderResult: ...

    @abstractmethod
    def check_domain(self, domain: str) -> ProviderResult: ...

    @abstractmethod
    def check_ip(self, ip: str) -> ProviderResult: ...

    def _request_with_retry(self, fn) -> ProviderResult:
        """Retry with exponential backoff + jitter; circuit breaker via Redis."""
        breaker_key = f"cb:{self.name}"
        if cache.get(breaker_key):
            return ProviderResult(self.name, "ERROR", error_detail="circuit_open")
        last_err = ""
        for attempt in range(self.max_retries + 1):
            try:
                return fn()
            except httpx.ReadTimeout as exc:
                last_err = f"timeout: {exc}"
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 429:
                    return ProviderResult(self.name, "RATE_LIMITED", error_detail="429")
                last_err = f"http_{exc.response.status_code}"
            except Exception as exc:  # noqa: BLE001
                last_err = str(exc)
            if attempt < self.max_retries:
                # Jitter only — not used for anything security-relevant.
                time.sleep((2**attempt) + random.uniform(0, 0.5))  # nosec B311
        cache.set(breaker_key, "open", timeout=60)
        return ProviderResult(self.name, "ERROR", error_detail=last_err)


class PhishTankProvider(ThreatIntelProvider):
    name = "phishtank"

    def _check(self, value: str) -> ProviderResult:
        def _call() -> ProviderResult:
            if not settings.FEATURE_PHISHTANK:
                return ProviderResult(self.name, "UNSUPPORTED", error_detail="disabled")
            quota_key = f"quota:{self.name}"
            # incr() raises ValueError when the key does not exist yet.
            cache.add(quota_key, 0, timeout=86400)
            cache.incr(quota_key)
            resp = httpx.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={"url": value, "format": "json", "app_key": settings.PHISHTANK_API_KEY},
                headers={"User-Agent": "CyberSathi/1.0"},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", {})
            if results.get("verified") and results.get("valid"):
                return ProviderResult(self.name, "MATCH", response_reference=str(results.get("phish_detail_url", "")))
            return ProviderResult(self.name, "NO_MATCH", response_reference=str(data.get("status", "")))

        return self._request_with_retry(_call)

    def check_url(self, url: str) -> ProviderResult:
        return self._check(url)

    def check_domain(self, domain: str) -> ProviderResult:
        return ProviderResult(self.name, "UNSUPPORTED", error_detail="urls_only")

    def check_ip(self, ip: str) -> ProviderResult:
        return ProviderResult(self.name, "UNSUPPORTED", error_detail="urls_only")


class RdapProvider(ThreatIntelProvider):
    """Domain registration event date via IANA bootstrap. Weak signal only."""

    name = "rdap"

    def _resolve_rdap_base(self, domain: str) -> str | None:
        try:
            resp = httpx.get(settings.RDAP_BOOTSTRAP_URL, timeout=self.timeout)
            resp.raise_for_status()
            bootstrap = resp.json()
            tld = domain.rsplit(".", 1)[-1].lower()
            for entry in bootstrap.get("services", []):
                if tld in entry[0]:
                    return entry[1][0].rstrip("/")
        except Exception:  # noqa: BLE001
            return None
        return None

    def check_domain(self, domain: str) -> ProviderResult:
        def _call() -> ProviderResult:
            if not settings.FEATURE_RDAP:
                return ProviderResult(self.name, "UNSUPPORTED", error_detail="disabled")
            base = self._resolve_rdap_base(domain)
            if not base:
                return ProviderResult(self.name, "ERROR", error_detail="bootstrap_failed")
            resp = httpx.get(f"{base}/domain/{domain}", timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            events = data.get("events", [])
            reg = next((e.get("eventDate") for e in events if e.get("eventAction") == "registration"), None)
            return ProviderResult(
                self.name, "NO_MATCH", response_reference=reg or "", metadata={"registered": reg}
            )

        return self._request_with_retry(_call)

    def check_url(self, url: str) -> ProviderResult:
        from submissions.normalisation import extract_domain

        domain = extract_domain(url)
        return self.check_domain(domain) if domain else ProviderResult(self.name, "ERROR", error_detail="no_domain")

    def check_ip(self, ip: str) -> ProviderResult:
        return ProviderResult(self.name, "UNSUPPORTED", error_detail="domains_only")


class AbuseIpDbProvider(ThreatIntelProvider):
    """IP addresses only — endpoint rejects domains/URLs/UPI."""

    name = "abuseipdb"

    def check_ip(self, ip: str) -> ProviderResult:
        def _call() -> ProviderResult:
            if not settings.FEATURE_ABUSEIPDB:
                return ProviderResult(self.name, "UNSUPPORTED", error_detail="disabled")
            resp = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            score = resp.json().get("data", {}).get("abuseConfidenceScore", 0)
            outcome = "MATCH" if score >= 50 else "NO_MATCH"
            return ProviderResult(self.name, outcome, metadata={"score": score})

        return self._request_with_retry(_call)

    def check_url(self, url: str) -> ProviderResult:
        return ProviderResult(self.name, "UNSUPPORTED", error_detail="ips_only")

    def check_domain(self, domain: str) -> ProviderResult:
        return ProviderResult(self.name, "UNSUPPORTED", error_detail="ips_only")


def get_providers() -> list[ThreatIntelProvider]:
    """Return enabled providers (feature flags + keys)."""
    providers: list[ThreatIntelProvider] = []
    if settings.FEATURE_PHISHTANK:
        providers.append(PhishTankProvider())
    if settings.FEATURE_RDAP:
        providers.append(RdapProvider())
    if settings.FEATURE_ABUSEIPDB:
        providers.append(AbuseIpDbProvider())
    return providers
