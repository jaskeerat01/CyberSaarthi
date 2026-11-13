"""Local store for the OpenPhish community feed (ingested every 12h via n8n).

The feed is pulled on a schedule into this table — never queried per request.
"""

from __future__ import annotations

from django.db import models
from django.db.models.functions import Now


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
        """Concurrent-safe ingest of (digest, url) pairs. Returns new count.

        Uses one SELECT + one bulk INSERT + batched UPDATEs instead of a
        get_or_create round-trip per row: a 10k-entry feed previously issued
        ~30k queries per sync.
        """
        if not digests_and_urls:
            return 0

        # De-duplicate within the batch (feed lines can repeat) so the count
        # and the insert payload stay consistent.
        seen: set[bytes] = set()
        unique: list[tuple[bytes, str]] = []
        for digest, url in digests_and_urls:
            key = bytes(digest)
            if key in seen:
                continue
            seen.add(key)
            unique.append((key, url))

        batch_size = 1000
        existing: set[bytes] = set()
        for start in range(0, len(unique), batch_size):
            chunk = [digest for digest, _ in unique[start : start + batch_size]]
            existing.update(
                bytes(value)
                for value in cls.objects.filter(digest__in=chunk).values_list(
                    "digest", flat=True
                )
            )

        new_rows = [
            cls(digest=digest, url=url)
            for digest, url in unique
            if digest not in existing
        ]
        cls.objects.bulk_create(new_rows, ignore_conflicts=True, batch_size=batch_size)

        if existing:
            now = Now()
            existing_list = list(existing)
            for start in range(0, len(existing_list), batch_size):
                cls.objects.filter(
                    digest__in=existing_list[start : start + batch_size]
                ).update(last_seen=now)
        return len(new_rows)

    @classmethod
    def matching_digests(cls, digests: list[bytes]) -> set[bytes]:
        """Which of the given digests appear in the active feed."""
        return set(
            cls.objects.filter(digest__in=digests, active=True).values_list(
                "digest", flat=True
            )
        )
