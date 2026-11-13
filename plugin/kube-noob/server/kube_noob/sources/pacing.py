"""Jittered pacing for every fetch kube-noob makes from a public source (Jira, GitHub clones, release notes).

A fleet of pods or a scheduled job that starts on the minute and fetches at a fixed rhythm looks like a bot and
lands on the source at the same moment as everyone else. Every enrichment therefore waits a random time before its
first request and between steps, and repeats on an interval with random spread. Randomness here is for pacing, not
security.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable

START_DELAY = (30.0, 600.0)  # seconds before a background sync's first run after the service starts
INTERVAL_SPREAD = 0.1  # a repeating sync runs every interval +/- 10%
CLONE_PAUSE = (1.0, 4.0)  # seconds between two clones from the same host


def start_delay(rng: random.Random | None = None, bounds: tuple[float, float] = START_DELAY) -> float:
    """Seconds to wait before a background job's first run."""
    low, high = bounds
    return (rng or random.Random()).uniform(low, high)  # noqa: S311 - pacing, not crypto


def jittered_interval(seconds: float, rng: random.Random | None = None, spread: float = INTERVAL_SPREAD) -> float:
    """``seconds`` +/- ``spread`` (a fraction), never below one minute."""
    r = rng or random.Random()  # noqa: S311 - pacing, not crypto
    return max(60.0, seconds * (1.0 + r.uniform(-spread, spread)))


def pause(
    bounds: tuple[float, float] = CLONE_PAUSE,
    rng: random.Random | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> float:
    """Sleep a random time within ``bounds``; returns it."""
    low, high = bounds
    delay = (rng or random.Random()).uniform(low, high)  # noqa: S311 - pacing, not crypto
    sleep(delay)
    return delay
