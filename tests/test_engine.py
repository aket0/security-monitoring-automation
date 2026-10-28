"""Integration tests for the monitoring engine."""

import io
import json
import time

from monitoring.detectors.brute_force import BruteForceConfig
from monitoring.engine import MonitoringEngine
from monitoring.event import EventType, SecurityEvent, Severity
from monitoring.response.handler import ResponseMode


def make_failure(ip: str = "1.2.3.4", ts: float | None = None) -> SecurityEvent:
    return SecurityEvent(
        event_type=EventType.LOGIN_FAILURE,
        source_ip=ip,
        username="user",
        message="Login failed",
        timestamp=ts or time.time(),
    )


class TestMonitoringEngine:
    def test_brute_force_triggers_alert(self):
        engine = MonitoringEngine(brute_force_config=BruteForceConfig(max_failures=3))
        alerts = []
        for _ in range(3):
            alerts.extend(engine.process(make_failure()))
        assert any(a.event_type == EventType.LOGIN_LOCKOUT for a in alerts)

    def test_stats_update_on_processing(self):
        engine = MonitoringEngine()
        engine.process(make_failure())
        assert engine.stats["events_processed"] == 1

    def test_alert_logged_to_stream(self):
        buf = io.StringIO()
        engine = MonitoringEngine(
            brute_force_config=BruteForceConfig(max_failures=3),
            min_alert_severity=Severity.HIGH,
            alert_stream=buf,
        )
        for _ in range(3):
            engine.process(make_failure())
        log_output = buf.getvalue()
        assert len(log_output) > 0
        lines = [line for line in log_output.strip().splitlines() if line]
        assert len(lines) >= 1
        data = json.loads(lines[0])
        assert data["event_type"] == EventType.LOGIN_LOCKOUT

    def test_observe_mode_no_destructive_execution(self):
        engine = MonitoringEngine(
            mode=ResponseMode.OBSERVE,
            brute_force_config=BruteForceConfig(max_failures=3),
        )
        for _ in range(3):
            engine.process(make_failure())
        for record in engine.responder.pending_approvals:
            destructive = [a for a in record.actions if a.requires_approval]
            assert all(not a.executed for a in destructive)

    def test_multiple_ips_tracked_independently(self):
        engine = MonitoringEngine(brute_force_config=BruteForceConfig(max_failures=3))
        ips_alerted = set()
        for ip in ("1.1.1.1", "2.2.2.2"):
            for _ in range(3):
                for alert in engine.process(make_failure(ip=ip)):
                    ips_alerted.add(alert.source_ip)
        assert "1.1.1.1" in ips_alerted
        assert "2.2.2.2" in ips_alerted
