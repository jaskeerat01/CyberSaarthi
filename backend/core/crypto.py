"""Encryption-at-rest (Fernet) + keyed HMAC digests with versioning."""

from __future__ import annotations

import base64
import hashlib
import hmac

from cryptography.fernet import Fernet
from django.conf import settings

_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        key = (settings.FIELD_ENCRYPTION_KEY or "").strip()
        if not key:
            # Dev fallback only — never in production
            key = Fernet.generate_key().decode()
        _fernet = Fernet(key.encode())
    return _fernet


def encrypt(plaintext: str) -> str:
    """Encrypt raw content at rest."""
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt raw content."""
    return _get_fernet().decrypt(ciphertext.encode()).decode()


def hmac_digest(value: str, key_version: str | None = None) -> tuple[bytes, str]:
    """HMAC-SHA256 digest. Never plain SHA-256."""
    key_b64 = (settings.IDENTIFIER_HMAC_KEY or "").strip()
    version = key_version or settings.IDENTIFIER_HMAC_KEY_ID
    if not key_b64:
        key = b"dev-key-only"
    else:
        key = base64.b64decode(key_b64)
    digest = hmac.new(key, value.encode(), hashlib.sha256).digest()
    return digest, version
