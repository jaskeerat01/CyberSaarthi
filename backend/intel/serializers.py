"""Serializers for internal (service-token-only) endpoints — schema docs only."""

from __future__ import annotations

from rest_framework import serializers


class ObservationSerializer(serializers.Serializer):
    """One provider observation posted by n8n (POST /internal/scans/{id}/enrichment)."""

    type = serializers.CharField(help_text="Indicator type, e.g. URL, DOMAIN, PHONE")
    normalised_value = serializers.CharField(required=False, allow_blank=True, default="")
    provider = serializers.CharField(help_text="Provider name, e.g. phishtank, virustotal")
    outcome = serializers.CharField(help_text="MATCH | NO_MATCH | ERROR | RATE_LIMITED")
    response_reference = serializers.CharField(required=False, allow_blank=True, default="")
    error_detail = serializers.CharField(required=False, allow_blank=True, default="")


class EnrichmentSerializer(serializers.Serializer):
    observations = ObservationSerializer(many=True, required=False, default=list)


class CompleteSerializer(serializers.Serializer):
    """Callback payload for POST /internal/scans/{id}/complete."""

    status = serializers.CharField(required=False, allow_blank=True, default="completed")


class OpenPhishIngestSerializer(serializers.Serializer):
    """Feed payload for POST /internal/openphish/ingest (n8n, every 12h)."""

    urls = serializers.ListField(child=serializers.CharField(), required=False, default=list)


class StatusSerializer(serializers.Serializer):
    status = serializers.CharField(read_only=True)
