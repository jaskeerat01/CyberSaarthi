"""Normalisation: NFKC, strip zero-width/control, IDNA, URL parsing, language detect."""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlparse

_ZERO_WIDTH = {"\u200b", "‌", "‍", "⁠", "﻿", "­"}

_URL_RE = re.compile(r"https?://[^\s\"'<>\]\)}]+|www\.[^\s\"'<>\]\)}]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_PHONE_RE = re.compile(r"(?:\+91[\s-]?|91[\s-]?|0)?[6-9](?:[\s-]?\d){9}")
_UPI_RE = re.compile(r"[\w.\-]{2,}@[a-zA-Z]{2,}")
_IP_RE = re.compile(
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
)
_DEVANAGARI_RE = re.compile(r"[\u0900-\u097F]")


def normalise_text(raw: str, max_chars: int = 5000) -> str:
    """NFKC + strip zero-width/control chars. Enforce max length."""
    if len(raw) > max_chars:
        raise ValueError(f"Input exceeds maximum of {max_chars} characters")
    text = unicodedata.normalize("NFKC", raw)
    text = "".join(ch for ch in text if ch not in _ZERO_WIDTH and unicodedata.category(ch)[0] != "C")
    return text.strip()


def detect_language(text: str) -> str:
    """Return 'en', 'hi', or 'mixed'."""
    has_dev = bool(_DEVANAGARI_RE.search(text))
    has_latin = bool(re.search(r"[A-Za-z]", text))
    if has_dev and has_latin:
        return "mixed"
    if has_dev:
        return "hi"
    return "en"


def extract_urls(text: str) -> list[str]:
    """Extract URLs with normalisation; reject embedded credentials."""
    urls: list[str] = []
    for m in _URL_RE.finditer(text):
        candidate = m.group(0).rstrip(".,;:!?)]}")
        normalised = normalise_url(candidate)
        if normalised:
            urls.append(normalised)
    return urls


def normalise_url(raw: str) -> str | None:
    """Normalise a single URL. Returns None if invalid or has embedded credentials."""
    candidate = raw.strip()
    if "://" not in candidate:
        candidate = "https://" + candidate
    parsed = urlparse(candidate)
    if not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None  # Reject URLs containing embedded credentials
    host = parsed.hostname.lower().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    port = parsed.port
    scheme = parsed.scheme.lower()
    default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    netloc = host if (port is None or default_port) else f"{host}:{port}"
    path = parsed.path or "/"
    return f"{scheme}://{netloc}{path}"


def extract_domain(url: str) -> str | None:
    """Extract normalised hostname from a URL."""
    try:
        return urlparse(url).hostname
    except Exception:  # noqa: BLE001
        return None


def extract_emails(text: str) -> list[str]:
    """Extract email addresses (lowercased)."""
    return [m.group(0).lower() for m in _EMAIL_RE.finditer(text)]


def extract_phones(text: str) -> list[str]:
    """Extract Indian phone numbers, normalised to 10 digits."""
    phones: list[str] = []
    for m in _PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if len(digits) == 12 and digits.startswith("91"):
            digits = digits[2:]
        elif len(digits) == 11 and digits.startswith("0"):
            digits = digits[1:]
        if len(digits) == 10:
            phones.append(digits)
    return phones


def extract_upi_ids(text: str) -> list[str]:
    """Extract UPI IDs (local@handle)."""
    return [m.group(0).lower() for m in _UPI_RE.finditer(text)
            if not m.group(0).lower().endswith((".com", ".in", ".org", ".net"))]


def extract_ips(text: str) -> list[str]:
    """Extract IPv4 addresses."""
    return [m.group(0) for m in _IP_RE.finditer(text)]
