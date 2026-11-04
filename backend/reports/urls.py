from django.urls import path

from .views import report_pdf

urlpatterns = [
    path("scans/<uuid:scan_id>/report.pdf", report_pdf, name="scan-report"),
]
