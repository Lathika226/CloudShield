"""
rate_limiter.py — Simple sliding-window rate limiter keyed by IP.
"""

import time
from collections import defaultdict
from threading import Lock
from typing import Tuple


class RateLimiter:
    """
    Sliding-window rate limiter.

    Args:
        max_requests:    Maximum number of requests allowed per window.
        window_seconds:  Duration of the sliding window in seconds.
    """

    def __init__(self, max_requests: int = 20, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def check(self, key: str) -> Tuple[bool, int]:
        """
        Check whether the given key (IP address) is within rate limits.

        Returns:
            (allowed, retry_after_seconds)
        """
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            timestamps = self._buckets[key]
            # Prune expired entries
            self._buckets[key] = [t for t in timestamps if t > cutoff]

            if len(self._buckets[key]) >= self.max_requests:
                oldest = self._buckets[key][0]
                retry_after = int(self.window_seconds - (now - oldest)) + 1
                return False, retry_after

            self._buckets[key].append(now)
            return True, 0

    def reset(self, key: str) -> None:
        """Clear rate-limit history for a given key."""
        with self._lock:
            self._buckets.pop(key, None)

    def remaining(self, key: str) -> int:
        """Return how many requests the key has left in the current window."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            active = [t for t in self._buckets.get(key, []) if t > cutoff]
            return max(0, self.max_requests - len(active))
