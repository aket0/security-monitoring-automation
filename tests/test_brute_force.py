"""Tests for the brute force detector."""

import time

from monitoring.detectors.brute_force import BruteForceConfig, BruteForceDetector
from monitoring.event import EventType, SecurityEvent, Severity


def make_failure(ip: str = "1.2.3.4", user: str = "alice", ts: float | None = None) -> SecurityEvent:
    return SecurityEvent(
        event_type=EventType.LOGIN_FAILURE,
        source_ip=ip,
        username=user,
        message="Login failed",
        severity=Severity.INFO,
        timestamp=ts or time.time(),
    )


class TestBruteForceDetector:
    def test_no_alert_below_threshold(self):
        detector = BruteForceDetector(BruteForceConfig(max_failures=5))
        for _ in range(4):
            result = detector.process(make_failure())
        assert result is None

    def test_alert_at_threshold(self):
        detector = BruteForceDetector(BruteForceConfig(max_failures=5))
        result = None
        for _ in range(5):
            result = detector.process(make_failure())
        assert result is not None
        assert result.event_type == EventType.LOGIN_LOCKOUT
        assert result.severity == Severity.HIGH

    def test_critical_above_lockout_threshold(self):
        # When lockout_threshold == max_failures, the first alert is CRITICAL
        cfg = BruteForceConfig(max_failures=5, lockout_threshold=5)
        detector = BruteForceDetector(cfg)
        result = None
        for _ in range(5):
            result = detector.process(make_failure())
        assert result is not None
        assert result.severity == Severity.CRITICAL

    def test_different_ips_independent(self):
        detector = BruteForceDetector(BruteForceConfig(max_failures=5))
        for _ in range(4):
            detector.process(make_failure(ip="1.1.1.1"))
        result = detector.process(make_failure(ip="2.2.2.2"))
        assert result is None  # second IP hasn't reached threshold

    def test_deduplication_within_window(self):
        now = time.time()
        detector = BruteForceDetector(BruteForceConfig(max_failures=3, window_seconds=300))
        alerts = []
        for i in range(10):
            alert = detector.process(make_failure(ts=now + i))
            if alert:
                alerts.append(alert)
        # Only one alert per window despite many failures
        assert len(alerts) == 1

    def test_window_expiry_resets_count(self):
        now = time.time()
        cfg = BruteForceConfig(max_failures=3, window_seconds=60)
        detector = BruteForceDetector(cfg)
        # Fill up past the window
        for i in range(3):
            detector.process(make_failure(ts=now - 120 + i))  # all outside window
        # Now send one failure in the current window
        result = detector.process(make_failure(ts=now))
        assert result is None  # old failures expired

    def test_ignores_non_failure_events(self):
        detector = BruteForceDetector(BruteForceConfig(max_failures=3))
        success = SecurityEvent(
            event_type=EventType.LOGIN_SUCCESS,
            source_ip="1.2.3.4",
            username="alice",
            message="Login OK",
        )
        result = detector.process(success)
        assert result is None

    def test_reset_clears_state(self):
        detector = BruteForceDetector(BruteForceConfig(max_failures=3))
        for _ in range(3):
            detector.process(make_failure())
        detector.reset("1.2.3.4")
        # After reset, threshold check starts fresh
        result = detector.process(make_failure())
        assert result is None
