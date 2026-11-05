import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
os.environ.setdefault("DJANGO_SECRET_KEY", "test-secret-key-32-chars-long!!")
os.environ.setdefault(
    "IDENTIFIER_HMAC_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)
os.environ.setdefault("FIELD_ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
os.environ.setdefault("INTERNAL_SERVICE_TOKEN", "test-internal-token")
os.environ.setdefault("DATABASE_URL", "sqlite:///db.sqlite3")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")


def pytest_configure(config):
    """Set up Django after the test environment above is in place.

    pytest-django only loads settings during initial-conftest loading when
    DJANGO_SETTINGS_MODULE comes from pytest config/env. Since this conftest
    owns that variable, finish the setup explicitly here.
    """
    import django

    django.setup()
