"""Scan assessments — deterministic, explainable, rule-tied."""

from __future__ import annotations

import uuid

from django.db import models

from submissions.models import ScamSubmission


class Classification(models.TextChoices):
    CONFIRMED_MALICIOUS = "CONFIRMED_MALICIOUS"
    HIGH_RISK = "HIGH_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    NO_KNOWN_THREAT_DETECTED = "NO_KNOWN_THREAT_DETECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class ScanAssessment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    submission = models.OneToOneField(ScamSubmission, on_delete=models.CASCADE, related_name="assessment")
    classification = models.CharField(max_length=32, choices=Classification.choices)
    technical_evidence = models.JSONField(default=dict)
    social_engineering_evidence = models.JSONField(default=dict)
    confidence = models.CharField(max_length=16, default="LOW")
    rule_ids = models.JSONField(default=list)
    ruleset_version = models.CharField(max_length=32, default="1.0")
    explanation_key = models.CharField(max_length=128, default="")
    created_at = models.DateTimeField(auto_now_add=True)
