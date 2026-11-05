"""Serializers for internal (service-token-only) endpoints."""

from __future__ import annotations

from rest_framework import serializers

INDICATOR_TYPES = ["URL", "DOMAIN", "IP", "PHONE", "UPI", "EMAIL"]
OUTCOMES = ["MATCH", "NO_MATCH", "ERROR", "RATE_LIMITED", "UNSUPPORTED"]


class ObservationSerializer(serializers.Serializer):
    """One provider observation posted by n8n (POST /internal/scans/{id}/enrichment)."""

    type = serializers.ChoiceField(choices=INDICATOR_TYPES)
    normalised_value = serializers.CharField(max_length=2048)
    provider = serializers.CharField(max_length=64)
    outcome = serializers.ChoiceField(choices=OUTCOMES)
    response_reference = serializers.CharField(required=False, allow_blank=True, default="")
    error_detail = serializers.CharField(required=False, allow_blank=True, default="")

    def to_internal_value(self, data):
        # Older n8n exports used indicator_type/indicator_value. Accept both
        # spellings so an un-updated workflow cannot silently corrupt digests.
        if isinstance(data, dict):
            data = data.copy()
            data.setdefault("type", data.get("indicator_type"))
            data.setdefault("normalised_value", data.get("indicator_value"))
        return super().to_internal_value(data)


class EnrichmentSerializer(serializers.Serializer):
    observations = ObservationSerializer(many=True, required=False, default=list)


class CompleteSerializer(serializers.Serializer):
    """Callback payload for POST /internal/scans/{id}/complete."""

    status = serializers.CharField(required=False, allow_blank=True, default="completed", max_length=64)


class WorkflowFailureSerializer(serializers.Serializer):
    """Failure event posted by the n8n Error Trigger workflow."""

    workflow_name = serializers.CharField(max_length=128)
    execution_id = serializers.CharField(max_length=64)
    failed_node = serializers.CharField(required=False, allow_blank=True, default="", max_length=128)
    error_message = serializers.CharField(
        required=False, allow_blank=True, default="", max_length=1000
    )
    occurred_at = serializers.CharField(required=False, allow_blank=True, default="", max_length=64)


class OpenPhishIngestSerializer(serializers.Serializer):
    """Feed payload for POST /internal/openphish/ingest (n8n, every 12h)."""

    urls = serializers.ListField(
        child=serializers.CharField(max_length=2048),
        required=False,
        default=list,
        max_length=10000,
    )


class StatusSerializer(serializers.Serializer):
    status = serializers.CharField(read_only=True)
