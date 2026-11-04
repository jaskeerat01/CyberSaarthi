from django.urls import path

from .views import create_scan, get_evidence, scan_detail

urlpatterns = [
    path("scans", create_scan, name="create-scan"),
    path("scans/<uuid:scan_id>", scan_detail, name="scan-detail"),
    path("scans/<uuid:scan_id>/evidence", get_evidence, name="scan-evidence"),
]
