"""Root URLconf."""

from __future__ import annotations

from django.urls import include, path
from drf_spectacular.generators import SchemaGenerator
from drf_spectacular.views import SpectacularAPIView

from core.views import healthz, metrics, readyz

urlpatterns = [
    path("healthz", healthz),
    path("readyz", readyz),
    path("metrics", metrics),
    path("api/v1/", include("submissions.urls")),
    path("api/v1/", include("reports.urls")),
    path("api/v1/", include("telegram.urls")),
    path("internal/", include("intel.internal_urls")),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
]

# Validate OpenAPI in CI via: python -m drf_spectacular
GENERATOR = SchemaGenerator()
