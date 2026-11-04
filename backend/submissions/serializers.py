"""DRF serializers for scans API."""

from __future__ import annotations

from rest_framework import serializers


class ScanCreateSerializer(serializers.Serializer):
    raw_content = serializers.CharField(max_length=5000)
    reported_financial_loss = serializers.BooleanField(default=False)
    channel = serializers.ChoiceField(choices=["web", "telegram"], default="web")


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
