"""Injectable time/random/id providers for reproducible preservation behavior."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import random
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime:
        """Return an offset-aware current time."""


class RandomSource(Protocol):
    def randbelow(self, upper_bound: int) -> int:
        """Return an integer in ``[0, upper_bound)``."""


class IdGenerator(Protocol):
    def new_id(self, namespace: str) -> str:
        """Return a new stable identifier within a semantic namespace."""


@dataclass(frozen=True)
class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


@dataclass(frozen=True)
class FixedClock:
    value: datetime

    def __post_init__(self) -> None:
        if self.value.tzinfo is None or self.value.utcoffset() is None:
            raise ValueError("FixedClock requires an offset-aware datetime")

    def now(self) -> datetime:
        return self.value


class SeededRandomSource:
    """Deterministic RNG for tests and reproducible archival profiles."""

    def __init__(self, seed: int | str | bytes | bytearray | None = 0) -> None:
        self._random = random.Random(seed)

    def randbelow(self, upper_bound: int) -> int:
        if upper_bound <= 0:
            raise ValueError("upper_bound must be positive")
        return self._random.randrange(upper_bound)


class SequentialIdGenerator:
    """Simple deterministic namespaced IDs; not a claim about production IDs."""

    def __init__(self) -> None:
        self._counters: dict[str, int] = {}

    def new_id(self, namespace: str) -> str:
        if not namespace:
            raise ValueError("namespace must be non-empty")
        value = self._counters.get(namespace, 0) + 1
        self._counters[namespace] = value
        return f"{namespace}:{value}"
