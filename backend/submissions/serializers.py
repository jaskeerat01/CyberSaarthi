"""DRF serializers for scans API."""

from __future__ import annotations

from django.conf import settings
from rest_framework import serializers


class ScanCreateSerializer(serializers.Serializer):
    # The effective limit comes from settings.MAX_INPUT_CHARS at request time
    # (validate_raw_content), so this must not hard-code 5000.
    raw_content = serializers.CharField()
    reported_financial_loss = serializers.BooleanField(default=False)
    channel = serializers.ChoiceField(choices=["web", "telegram"], default="web")

    def validate_raw_content(self, value: str) -> str:
        limit = getattr(settings, "MAX_INPUT_CHARS", 5000)
        if len(value) > limit:
            raise serializers.ValidationError(
                f"Ensure this field has no more than {limit} characters."
            )
        return value


class ScanDetailSerializer(serializers.Serializer):
    scan_id = serializers.UUIDField()
    status = serializers.CharField()
    reported_financial_loss = serializers.BooleanField()
    classification = serializers.CharField(required=False, allow_null=True)
    technical_evidence = serializers.JSONField(required=False)
    social_engineering_evidence = serializers.JSONField(required=False)
    confidence = serializers.CharField(required=False, allow_null=True)
    rule_ids = serializers.ListField(required=False)
    ruleset_version = serializers.CharField(required=False)
    explanation_key = serializers.CharField(required=False)
    disclaimer = serializers.CharField(required=False)
