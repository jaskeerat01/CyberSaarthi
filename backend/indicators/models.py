"""Threat indicators + observations. Strict state machine + concurrent-safe upserts."""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from django.db import models, transaction
from django.db.models import Q, QuerySet
from django.utils import timezone


class ThreatIndicatorStatus(models.TextChoices):
    REPORTED = "REPORTED"
    UNDER_REVIEW = "UNDER_REVIEW"
    CORROBORATED = "CORROBORATED"
    CONFIRMED = "CONFIRMED"
    EXPIRED = "EXPIRED"


# Allowed transitions — single user report only reaches REPORTED
_TRANSITIONS: dict[str, list[str]] = {
    ThreatIndicatorStatus.REPORTED: [ThreatIndicatorStatus.UNDER_REVIEW, ThreatIndicatorStatus.EXPIRED],
    ThreatIndicatorStatus.UNDER_REVIEW: [
        ThreatIndicatorStatus.CORROBORATED,
        ThreatIndicatorStatus.EXPIRED,
    ],
    ThreatIndicatorStatus.CORROBORATED: [
        ThreatIndicatorStatus.CONFIRMED,
        ThreatIndicatorStatus.EXPIRED,
    ],
    ThreatIndicatorStatus.CONFIRMED: [ThreatIndicatorStatus.EXPIRED],
    ThreatIndicatorStatus.EXPIRED: [],
}


class ThreatIndicator(models.Model):
    """Verified threat indicator keyed by HMAC digest."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    indicator_type = models.CharField(max_length=16)
    digest = models.BinaryField()
    status = models.CharField(
        max_length=16,
        choices=ThreatIndicatorStatus.choices,
        default=ThreatIndicatorStatus.REPORTED,
    )
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["indicator_type", "digest"], name="unique_type_digest"),
        ]
        indexes = [
            models.Index(fields=["indicator_type", "status"]),
            # NOTE: no standalone index on digest alone (per spec)
        ]

    def transition_to(self, new_status: str, *, trusted: bool = False) -> None:
        """Enforce state transitions. Promotion beyond REPORTED needs trust."""
        allowed = _TRANSITIONS.get(self.status, [])
        if new_status not in allowed:
            raise ValueError(f"Illegal transition {self.status} -> {new_status}")
        if new_status in (ThreatIndicatorStatus.CORROBORATED, ThreatIndicatorStatus.CONFIRMED) and not trusted:
            raise ValueError("Promotion requires trusted source or human review")
        self.status = new_status
        self.save(update_fields=["status", "last_seen"])


def threat_indicators_for(
    pairs: Iterable[tuple[str, bytes]],
) -> QuerySet[ThreatIndicator]:
    """Return indicators matching (indicator_type, digest) pairs exactly.

    Filtering ``indicator_type__in`` and ``digest__in`` separately returns the
    cartesian product; a digest is only meaningful together with its type.
    """
    query = Q()
    for indicator_type, digest in pairs:
        query |= Q(indicator_type=indicator_type, digest=digest)
    if not query:
        return ThreatIndicator.objects.none()
    return ThreatIndicator.objects.filter(query)


def upsert_indicator(indicator_type: str, digest: bytes) -> tuple[ThreatIndicator, bool]:
    """Concurrent-safe upsert. Returns (indicator, created)."""
    with transaction.atomic():
        obj, created = ThreatIndicator.objects.get_or_create(
            indicator_type=indicator_type,
            digest=digest,
            defaults={"status": ThreatIndicatorStatus.REPORTED},
        )
        if not created:
            obj.last_seen = timezone.now()
            obj.save(update_fields=["last_seen"])
        return obj, created


class IndicatorObservation(models.Model):
    """Per-provider observation against an indicator."""

    class Outcome(models.TextChoices):
        MATCH = "MATCH"
        NO_MATCH = "NO_MATCH"
        ERROR = "ERROR"
        RATE_LIMITED = "RATE_LIMITED"
        UNSUPPORTED = "UNSUPPORTED"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    indicator = models.ForeignKey(ThreatIndicator, on_delete=models.CASCADE, related_name="observations")
    provider = models.CharField(max_length=64)
    outcome = models.CharField(max_length=16, choices=Outcome.choices)
    observed_at = models.DateTimeField(auto_now_add=True)
    response_reference = models.TextField(blank=True, default="")
    error_detail = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["-observed_at"]
