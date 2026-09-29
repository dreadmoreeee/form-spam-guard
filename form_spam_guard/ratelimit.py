"""Per-key token-bucket rate limiter."""

from __future__ import annotations

import threading
import time
from typing import Callable, Dict, Tuple


class RateLimiter:
    """Token bucket per key (an IP address, an email...).

    Each key starts with ``capacity`` tokens and regains ``refill_per_second``
    tokens per second up to ``capacity``. ``allow`` spends ``cost`` tokens or
    returns False. Thread-safe; pass ``clock`` to control time in tests.
    """

    def __init__(
        self,
        capacity: float = 5.0,
        refill_per_second: float = 1.0 / 60.0,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 50000,
    ) -> None:
        if capacity <= 0 or refill_per_second < 0:
            raise ValueError("capacity must be > 0 and refill_per_second >= 0")
        self.capacity = float(capacity)
        self.refill = float(refill_per_second)
        self._clock = clock
        self._max_keys = max_keys
        self._buckets: Dict[str, Tuple[float, float]] = {}
        self._lock = threading.Lock()

    def _level(self, key: str, now: float) -> float:
        tokens, stamp = self._buckets.get(key, (self.capacity, now))
        return min(self.capacity, tokens + max(0.0, now - stamp) * self.refill)

    def allow(self, key: str, cost: float = 1.0) -> bool:
        with self._lock:
            now = self._clock()
            level = self._level(key, now)
            ok = level >= cost
            if ok:
                level -= cost
            if key not in self._buckets and len(self._buckets) >= self._max_keys:
                self._prune(now)
            self._buckets[key] = (level, now)
            return ok

    def remaining(self, key: str) -> float:
        with self._lock:
            return self._level(key, self._clock())

    def _prune(self, now: float) -> None:
        full = [k for k in self._buckets if self._level(k, now) >= self.capacity]
        for k in full:
            del self._buckets[k]
        while len(self._buckets) >= self._max_keys:
            del self._buckets[next(iter(self._buckets))]
