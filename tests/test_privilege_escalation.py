"""Tests for the privilege escalation detector."""


from monitoring.detectors.privilege_escalation import PrivilegeEscalationDetector
from monitoring.event import EventType, SecurityEvent, Severity


def make_event(event_type: EventType, **metadata) -> SecurityEvent:
    return SecurityEvent(
        event_type=event_type,
        source_ip="10.0.0.1",
        username="user1",
        message="test",
        metadata=metadata,
    )


class TestPrivilegeEscalationDetector:
    def test_sudo_command_triggers_critical(self):
        detector = PrivilegeEscalationDetector()
        event = make_event(EventType.SUSPICIOUS_PROCESS, command="sudo bash")
        alert = detector.process(event)
        assert alert is not None
        assert alert.event_type == EventType.PRIVILEGE_ESCALATION
        assert alert.severity == Severity.CRITICAL

    def test_su_command_triggers_critical(self):
        detector = PrivilegeEscalationDetector()
        alert = detector.process(make_event(EventType.SUSPICIOUS_PROCESS, command="su root"))
        assert alert is not None
        assert alert.severity == Severity.CRITICAL

    def test_benign_command_no_alert(self):
        detector = PrivilegeEscalationDetector()
        alert = detector.process(make_event(EventType.SUSPICIOUS_PROCESS, command="ls -la"))
        assert alert is None

    def test_sensitive_path_access_triggers_high(self):
        detector = PrivilegeEscalationDetector()
        alert = detector.process(make_event(EventType.FILE_ACCESS_DENIED, path="/etc/shadow"))
        assert alert is not None
        assert alert.severity == Severity.HIGH

    def test_sudoers_path_triggers_alert(self):
        detector = PrivilegeEscalationDetector()
        alert = detector.process(make_event(EventType.FILE_ACCESS_DENIED, path="/etc/sudoers"))
        assert alert is not None

    def test_benign_path_no_alert(self):
        detector = PrivilegeEscalationDetector()
        alert = detector.process(make_event(EventType.FILE_ACCESS_DENIED, path="/var/log/app.log"))
        assert alert is None

    def test_login_failure_ignored(self):
        detector = PrivilegeEscalationDetector()
        alert = detector.process(make_event(EventType.LOGIN_FAILURE))
        assert alert is None
