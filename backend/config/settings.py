"""Django settings. Fail-fast on missing core vars; providers warn+disable."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import environ

BASE_DIR = Path(__file__).resolve().parent.parent
env = environ.Env(
    DJANGO_SECRET_KEY=(str, ""),
    DJANGO_ALLOWED_HOSTS=(list, ["*"]),
    DATABASE_URL=(str, "sqlite:///db.sqlite3"),
    REDIS_URL=(str, "redis://localhost:6379/0"),
    IDENTIFIER_HMAC_KEY=(str, ""),
    IDENTIFIER_HMAC_KEY_ID=(str, "v1"),
    FIELD_ENCRYPTION_KEY=(str, ""),
    INTERNAL_SERVICE_TOKEN=(str, ""),
    MAX_INPUT_CHARS=(int, 5000),
    RETENTION_DAYS=(int, 30),
    FEATURE_PHISHTANK=(bool, False),
    FEATURE_RDAP=(bool, True),
    FEATURE_ABUSEIPDB=(bool, False),
    PHISHTANK_API_KEY=(str, ""),
    ABUSEIPDB_API_KEY=(str, ""),
    VIRUSTOTAL_ENABLED=(bool, False),
    VIRUSTOTAL_API_KEY=(str, ""),
    N8N_WEBHOOK_URL=(str, ""),
    N8N_WEBHOOK_TOKEN=(str, ""),
    SENTRY_DSN=(str, ""),
)

# --- fail-fast for core vars (not in pytest collection of settings-only tests) ---
_CORE_REQUIRED = ["DJANGO_SECRET_KEY", "IDENTIFIER_HMAC_KEY", "FIELD_ENCRYPTION_KEY"]
_missing = [k for k in _CORE_REQUIRED if not os.environ.get(k)]
if _missing and "pytest" not in sys.modules and len(sys.argv) > 1:
    raise RuntimeError(f"Missing required env vars: {', '.join(_missing)}")

SECRET_KEY = env("DJANGO_SECRET_KEY") or "dev-insecure-change-me"
DEBUG = env.bool("DJANGO_DEBUG", default=False)
ALLOWED_HOSTS = env("DJANGO_ALLOWED_HOSTS")

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "rest_framework",
    "drf_spectacular",
    "core",
    "submissions",
    "indicators",
    "intel",
    "assessment",
    "reports",
    "telegram",
]

MIDDLEWARE = [
    "django.middleware.common.CommonMiddleware",
    "core.middleware.SecurityHeadersMiddleware",
    "core.middleware.JsonLoggingMiddleware",
]

ROOT_URLCONF = "config.urls"
DATABASES = {"default": env.db("DATABASE_URL")}
USE_TZ = True

REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.ScopedRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "submissions": "30/hour",
        "reports": "10/hour",
        "default": "120/minute",
    },
}

# Security headers
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = "DENY"

# App config
MAX_INPUT_CHARS = env("MAX_INPUT_CHARS")
RETENTION_DAYS = env("RETENTION_DAYS")
IDENTIFIER_HMAC_KEY = env("IDENTIFIER_HMAC_KEY")
IDENTIFIER_HMAC_KEY_ID = env("IDENTIFIER_HMAC_KEY_ID")
FIELD_ENCRYPTION_KEY = env("FIELD_ENCRYPTION_KEY")
INTERNAL_SERVICE_TOKEN = env("INTERNAL_SERVICE_TOKEN")

# Provider feature flags — missing key disables + warns
FEATURE_PHISHTANK = env("FEATURE_PHISHTANK") and bool(env("PHISHTANK_API_KEY"))
FEATURE_RDAP = env("FEATURE_RDAP")
FEATURE_ABUSEIPDB = env("FEATURE_ABUSEIPDB") and bool(env("ABUSEIPDB_API_KEY"))
PHISHTANK_API_KEY = env("PHISHTANK_API_KEY")
ABUSEIPDB_API_KEY = env("ABUSEIPDB_API_KEY")
VIRUSTOTAL_ENABLED = env("VIRUSTOTAL_ENABLED")
VIRUSTOTAL_API_KEY = env("VIRUSTOTAL_API_KEY")
N8N_WEBHOOK_URL = env("N8N_WEBHOOK_URL")
N8N_WEBHOOK_TOKEN = env("N8N_WEBHOOK_TOKEN")

if env("FEATURE_PHISHTANK") and not PHISHTANK_API_KEY:
    import warnings

    warnings.warn("FEATURE_PHISHTANK=true but PHISHTANK_API_KEY missing — disabled")
if env("FEATURE_ABUSEIPDB") and not ABUSEIPDB_API_KEY:
    import warnings

    warnings.warn("FEATURE_ABUSEIPDB=true but ABUSEIPDB_API_KEY missing — disabled")

# Celery
CELERY_BROKER_URL = env("REDIS_URL")
CELERY_RESULT_BACKEND = env("REDIS_URL")
CELERY_TASK_ALWAYS_EAGER = env.bool("CELERY_TASK_ALWAYS_EAGER", default=True)
CELERY_TASK_SOFT_TIME_LIMIT = 120
CELERY_TASK_TIME_LIMIT = 180
CELERY_TASK_ACKS_LATE = True
CELERY_TASK_REJECT_ON_WORKER_LOST = True

# Retention purge (§14): raw content lives only for the configured window
CELERY_BEAT_SCHEDULE = {
    "purge-expired-raw-content-daily": {
        "task": "submissions.purge_expired_raw_content",
        "schedule": 24 * 3600.0,
    }
}

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "pythonjsonlogger.json.JsonFormatter",
            "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
        }
    },
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "json"}},
    "root": {"handlers": ["console"], "level": "INFO"},
}

if env("SENTRY_DSN"):
    import sentry_sdk

    sentry_sdk.init(dsn=env("SENTRY_DSN"))
