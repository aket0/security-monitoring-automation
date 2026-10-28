"""Brute force / credential stuffing detection."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ..event import EventType, SecurityEvent, Severity


@dataclass
class BruteForceConfig:
    max_failures: int = 5
    window_seconds: int = 300  # 5-minute sliding window
    lockout_threshold: int = 10  # trigger CRITICAL above this count


@dataclass
class _IpState:
    timestamps: list[float] = field(default_factory=list)


class BruteForceDetector:
    """
    Detect repeated login failures from a single IP within a time window.

    Deduplication: only one alert is emitted per IP per window.
    """

    def __init__(self, config: BruteForceConfig | None = None) -> None:
        self._config = config or BruteForceConfig()
        self._state: dict[str, _IpState] = defaultdict(_IpState)
        self._alerted: dict[str, float] = {}  # ip → last alert timestamp

    def process(self, event: SecurityEvent) -> SecurityEvent | None:
        """Return an alert event if a brute force is detected, else None."""
        if event.event_type != EventType.LOGIN_FAILURE:
            return None

        ip = event.source_ip
        now = event.timestamp
        cutoff = now - self._config.window_seconds

        state = self._state[ip]
        state.timestamps.append(now)
        # Prune old timestamps outside the window
        state.timestamps = [t for t in state.timestamps if t >= cutoff]

        count = len(state.timestamps)
        if count < self._config.max_failures:
            return None

        # Deduplication: suppress if we already alerted for this IP this window
        last_alert = self._alerted.get(ip, 0.0)
        if now - last_alert < self._config.window_seconds:
            return None

        self._alerted[ip] = now

        severity = (
            Severity.CRITICAL if count >= self._config.lockout_threshold
            else Severity.HIGH
        )

        return SecurityEvent(
            event_type=EventType.LOGIN_LOCKOUT,
            source_ip=ip,
            username=event.username,
            severity=severity,
            message=(
                f"Brute force detected: {count} failed login attempts "
                f"from {ip} in {self._config.window_seconds}s"
            ),
            timestamp=now,
            metadata={"failure_count": count, "window_seconds": self._config.window_seconds},
        )

    def reset(self, ip: str | None = None) -> None:
        """Reset state for an IP (or all IPs if ip is None)."""
        if ip is None:
            self._state.clear()
            self._alerted.clear()
        else:
            self._state.pop(ip, None)
            self._alerted.pop(ip, None)
