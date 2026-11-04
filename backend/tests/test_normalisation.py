"""Unit tests: normalisation, extraction, language detection."""

import pytest

from submissions.normalisation import (
    detect_language,
    extract_emails,
    extract_ips,
    extract_phones,
    extract_upi_ids,
    extract_urls,
    normalise_text,
    normalise_url,
)


class TestNormaliseText:
    def test_nfkc_and_zero_width(self):
        text = normalise_text("Hello\u200b world")
        assert "\u200b" not in text
        assert text == "Hello world"

    def test_control_strip(self):
        text = normalise_text("a\x00b\x1fc")
        assert "\x00" not in text

    def test_max_length(self):
        with pytest.raises(ValueError):
            normalise_text("x" * 5001)


class TestNormaliseUrl:
    def test_lowercase_and_default_port(self):
        assert normalise_url("HTTPS://Example.COM:443/path") == "https://example.com/path"

    def test_trailing_dot(self):
        assert normalise_url("https://example.com./") == "https://example.com/"

    def test_embedded_credentials_rejected(self):
        assert normalise_url("https://user:pass@example.com/") is None

    def test_idna(self):
        result = normalise_url("https://मुंबई.example/")
        assert result is not None
        assert "xn--" in result


class TestExtraction:
    def test_urls(self):
        urls = extract_urls("Visit https://evil.example.com/login and http://a.io/x.")
        assert len(urls) == 2

    def test_emails(self):
        assert extract_emails("Contact test@Example.COM") == ["test@example.com"]

    def test_phones(self):
        assert extract_phones("Call +91 98765 43210 now") == ["9876543210"]

    def test_upi(self):
        ids = extract_upi_ids("Pay to user@okhdfcbank")
        assert ids == ["user@okhdfcbank"]

    def test_ips(self):
        assert extract_ips("From 192.168.1.1 to 8.8.8.8") == ["192.168.1.1", "8.8.8.8"]


class TestLanguage:
    def test_english(self):
        assert detect_language("Hello world") == "en"

    def test_hindi(self):
        assert detect_language("तुरंत कार्रवाई करें") == "hi"

    def test_mixed(self):
        assert detect_language("Hello तुरंत") == "mixed"
