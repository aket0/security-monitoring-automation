"""Tests for the alert logger — verifies privacy and severity filtering."""

import io
import json

from monitoring.alerting.logger import AlertLogger
from monitoring.event import EventType, SecurityEvent, Severity


def make_event(severity: Severity = Severity.HIGH, **meta) -> SecurityEvent:
    return SecurityEvent(
        event_type=EventType.LOGIN_LOCKOUT,
        source_ip="1.2.3.4",
        username="user",
        message="test alert",
        severity=severity,
        metadata=meta,
    )


class TestAlertLogger:
    def test_emits_json_line(self):
        buf = io.StringIO()
        logger = AlertLogger(stream=buf, min_severity=Severity.INFO)
        logger.emit(make_event(Severity.HIGH))
        data = json.loads(buf.getvalue().strip())
        assert data["event_type"] == EventType.LOGIN_LOCKOUT

    def test_severity_filter_blocks_low(self):
        buf = io.StringIO()
        logger = AlertLogger(stream=buf, min_severity=Severity.HIGH)
        emitted = logger.emit(make_event(Severity.LOW))
        assert not emitted
        assert buf.getvalue() == ""

    def test_severity_filter_passes_high(self):
        buf = io.StringIO()
        logger = AlertLogger(stream=buf, min_severity=Severity.HIGH)
        emitted = logger.emit(make_event(Severity.HIGH))
        assert emitted

    def test_severity_filter_passes_critical(self):
        buf = io.StringIO()
        logger = AlertLogger(stream=buf, min_severity=Severity.HIGH)
        emitted = logger.emit(make_event(Severity.CRITICAL))
        assert emitted

    def test_password_in_metadata_redacted(self):
        buf = io.StringIO()
        logger = AlertLogger(stream=buf, min_severity=Severity.INFO)
        logger.emit(make_event(Severity.HIGH, password="supersecret"))
        data = json.loads(buf.getvalue().strip())
        assert data["metadata"]["password"] == "[REDACTED]"
        assert "supersecret" not in buf.getvalue()

    def test_token_in_metadata_redacted(self):
        buf = io.StringIO()
        logger = AlertLogger(stream=buf, min_severity=Severity.INFO)
        logger.emit(make_event(Severity.HIGH, token="abc123"))
        data = json.loads(buf.getvalue().strip())
        assert data["metadata"]["token"] == "[REDACTED]"

    def test_non_sensitive_metadata_preserved(self):
        buf = io.StringIO()
        logger = AlertLogger(stream=buf, min_severity=Severity.INFO)
        logger.emit(make_event(Severity.HIGH, failure_count=5))
        data = json.loads(buf.getvalue().strip())
        assert data["metadata"]["failure_count"] == 5
