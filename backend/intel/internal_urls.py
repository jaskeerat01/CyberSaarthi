from django.urls import path

from .internal_views import complete, enrichment, openphish_ingest

urlpatterns = [
    path("scans/<uuid:scan_id>/enrichment", enrichment, name="internal-enrichment"),
    path("scans/<uuid:scan_id>/complete", complete, name="internal-complete"),
    path("openphish/ingest", openphish_ingest, name="internal-openphish-ingest"),
]
