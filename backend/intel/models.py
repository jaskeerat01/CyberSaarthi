"""Local store for the OpenPhish community feed (ingested every 12h via n8n).

The feed is pulled on a schedule into this table — never queried per request.
"""

from __future__ import annotations

from django.db import models


class OpenPhishEntry(models.Model):
    """One URL from the community feed."""

    digest = models.BinaryField(unique=True)
    url = models.TextField()  # encrypted at rest in a later hardening pass; feed data is public
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    active = models.BooleanField(default=True)

    class Meta:
        indexes = [models.Index(fields=["active"])]

    @classmethod
    def ingest_urls(cls, digests_and_urls: list[tuple[bytes, str]]) -> int:
        """Concurrent-safe ingest of (digest, url) pairs. Returns new count."""
        created = 0
        for digest, url in digests_and_urls:
            _, was_created = cls.objects.get_or_create(
                digest=digest, defaults={"url": url}
            )
            if was_created:
                created += 1
            else:
                cls.objects.filter(digest=digest).update(last_seen=models.functions.Now())
        return created

    @classmethod
    def matching_digests(cls, digests: list[bytes]) -> set[bytes]:
        """Which of the given digests appear in the active feed."""
        return set(
            cls.objects.filter(digest__in=digests, active=True).values_list(
                "digest", flat=True
            )
        )
