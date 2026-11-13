"""Scam submissions + extracted indicators + workflow events."""

from __future__ import annotations

import uuid
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone

from core.crypto import decrypt, encrypt


class Channel(models.TextChoices):
    WEB = "web"
    TELEGRAM = "telegram"


class ScanStatus(models.TextChoices):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ScamSubmission(models.Model):
    """Citizen-submitted suspicious content. Raw content encrypted at rest."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    channel = models.CharField(max_length=16, choices=Channel.choices, default=Channel.WEB)
    input_type = models.CharField(max_length=16, default="text")
    raw_content_encrypted = models.TextField()
    # Content-hash idempotency lookup (find_existing_by_content) filters on
    # (content_hash, created_at) on every submission write; without an index
    # that is a full table scan. BinaryField supports btree indexes on
    # PostgreSQL (bytea) and SQLite (blob).
    content_hash = models.BinaryField(null=True, blank=True, db_index=True)
    status = models.CharField(max_length=16, choices=ScanStatus.choices, default=ScanStatus.PENDING)
    reported_financial_loss = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    # The daily retention purge scans on this column.
    retention_expires_at = models.DateTimeField(null=True, blank=True, db_index=True)

    class Meta:
        indexes = [models.Index(fields=["status", "created_at"])]

    @property
    def raw_content(self) -> str:
        return decrypt(self.raw_content_encrypted)

    @raw_content.setter
    def raw_content(self, value: str) -> None:
        self.raw_content_encrypted = encrypt(value)
        if not self.retention_expires_at:
            self.retention_expires_at = timezone.now() + timedelta(days=settings.RETENTION_DAYS)

    def delete_content(self) -> None:
        """User-initiated deletion of raw content."""
        self.raw_content_encrypted = ""
        self.save(update_fields=["raw_content_encrypted"])


class ExtractedIndicator(models.Model):
    """Indicator extracted from a submission."""

    class IndicatorType(models.TextChoices):
        URL = "URL"
        DOMAIN = "DOMAIN"
        IP = "IP"
        PHONE = "PHONE"
        UPI = "UPI"
        EMAIL = "EMAIL"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    submission = models.ForeignKey(ScamSubmission, on_delete=models.CASCADE, related_name="indicators")
    indicator_type = models.CharField(max_length=16, choices=IndicatorType.choices)
    normalised_value_encrypted = models.TextField()
    digest = models.BinaryField()
    key_version = models.CharField(max_length=32, default="v1")

    class Meta:
        unique_together = [("submission", "indicator_type", "digest")]

    @property
    def normalised_value(self) -> str:
        return decrypt(self.normalised_value_encrypted)

    @normalised_value.setter
    def normalised_value(self, value: str) -> None:
        self.normalised_value_encrypted = encrypt(value)


class WorkflowEvent(models.Model):
    """Audit trail for every scan pipeline stage."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(ScamSubmission, on_delete=models.CASCADE, related_name="events")
    event_type = models.CharField(max_length=64)
    attempt = models.PositiveSmallIntegerField(default=1)
    payload_summary = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]
        indexes = [
            # complete() and audit views filter (scan, event_type) repeatedly.
            models.Index(fields=["scan", "event_type"]),
        ]
