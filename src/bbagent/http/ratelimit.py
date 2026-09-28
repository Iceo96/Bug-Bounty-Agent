"""Async token-bucket rate limiter with optional per-host buckets and concurrency caps."""

from __future__ import annotations

import asyncio
import time
from urllib.parse import urlsplit

from bbagent.config.models import RateLimit


class _TokenBucket:
    def __init__(self, rate: float, capacity: float):
        self._rate = rate
        self._capacity = max(1.0, capacity)
        self._tokens = self._capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(self._capacity, self._tokens + (now - self._updated) * self._rate)
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                deficit = 1.0 - self._tokens
                await asyncio.sleep(deficit / self._rate)


class RateLimiter:
    """Combines a token bucket (throughput) with a semaphore (concurrency)."""

    def __init__(self, config: RateLimit):
        self._config = config
        self._buckets: dict[str, _TokenBucket] = {}
        self._sems: dict[str, asyncio.Semaphore] = {}

    def _key(self, url: str) -> str:
        if not self._config.per_host:
            return "*"
        return (urlsplit(url).hostname or "*").lower()

    def _bucket(self, key: str) -> _TokenBucket:
        if key not in self._buckets:
            self._buckets[key] = _TokenBucket(
                rate=self._config.requests_per_second,
                capacity=self._config.requests_per_second,
            )
        return self._buckets[key]

    def _sem(self, key: str) -> asyncio.Semaphore:
        if key not in self._sems:
            self._sems[key] = asyncio.Semaphore(self._config.max_concurrent)
        return self._sems[key]

    def slot(self, url: str) -> "_RateSlot":
        key = self._key(url)
        return _RateSlot(self._bucket(key), self._sem(key))


class _RateSlot:
    def __init__(self, bucket: _TokenBucket, sem: asyncio.Semaphore):
        self._bucket = bucket
        self._sem = sem

    async def __aenter__(self) -> "_RateSlot":
        await self._sem.acquire()
        try:
            await self._bucket.acquire()
        except BaseException:
            self._sem.release()
            raise
        return self

    async def __aexit__(self, *exc) -> None:
        self._sem.release()
