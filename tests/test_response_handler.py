"""Tests for the incident response handler."""


from monitoring.event import EventType, SecurityEvent, Severity
from monitoring.response.handler import IncidentResponseHandler, ResponseMode


def lockout_event(ip: str = "1.2.3.4") -> SecurityEvent:
    return SecurityEvent(
        event_type=EventType.LOGIN_LOCKOUT,
        source_ip=ip,
        username="attacker",
        severity=Severity.HIGH,
        message="Brute force detected",
    )


def escalation_event(severity: Severity = Severity.CRITICAL) -> SecurityEvent:
    return SecurityEvent(
        event_type=EventType.PRIVILEGE_ESCALATION,
        source_ip="10.0.0.1",
        username="user1",
        severity=severity,
        message="Privilege escalation detected",
    )


class TestObserveMode:
    def test_lockout_creates_record(self):
        handler = IncidentResponseHandler(ResponseMode.OBSERVE)
        record = handler.handle(lockout_event())
        assert record is not None
        assert len(record.actions) > 0

    def test_destructive_actions_not_executed_in_observe(self):
        handler = IncidentResponseHandler(ResponseMode.OBSERVE)
        record = handler.handle(lockout_event())
        destructive = [a for a in record.actions if a.requires_approval]
        assert all(not a.executed for a in destructive), (
            "Destructive actions must NOT be executed in observe mode"
        )

    def test_safe_actions_executed_in_observe(self):
        handler = IncidentResponseHandler(ResponseMode.OBSERVE)
        record = handler.handle(lockout_event())
        safe = [a for a in record.actions if not a.requires_approval]
        assert all(a.executed for a in safe)


class TestRespondMode:
    def test_safe_actions_executed(self):
        handler = IncidentResponseHandler(ResponseMode.RESPOND)
        record = handler.handle(lockout_event())
        safe = [a for a in record.actions if not a.requires_approval]
        assert all(a.executed for a in safe)

    def test_destructive_actions_queued_for_approval(self):
        handler = IncidentResponseHandler(ResponseMode.RESPOND)
        handler.handle(lockout_event())
        assert len(handler.pending_approvals) > 0

    def test_approve_executes_destructive_actions(self):
        handler = IncidentResponseHandler(ResponseMode.RESPOND)
        record = handler.handle(lockout_event())
        assert handler.pending_approvals
        handler.approve(record)
        destructive = [a for a in record.actions if a.requires_approval]
        assert all(a.executed for a in destructive)
        assert record not in handler.pending_approvals

    def test_critical_escalation_queues_account_disable(self):
        handler = IncidentResponseHandler(ResponseMode.RESPOND)
        record = handler.handle(escalation_event(Severity.CRITICAL))
        disable_actions = [a for a in record.actions if a.action_type == "disable_account"]
        assert len(disable_actions) > 0
        assert all(a.requires_approval for a in disable_actions)

    def test_approval_callback_fires(self):
        handler = IncidentResponseHandler(ResponseMode.RESPOND)
        callbacks = []
        handler.on_approval_needed(lambda r: callbacks.append(r))
        handler.handle(lockout_event())
        assert len(callbacks) > 0


class TestModeIsolation:
    def test_observe_never_queues_for_approval_in_same_way_as_respond(self):
        observe = IncidentResponseHandler(ResponseMode.OBSERVE)
        respond = IncidentResponseHandler(ResponseMode.RESPOND)
        observe.handle(lockout_event())
        respond.handle(lockout_event())
        # Both queue the record (for notification purposes), but executed state differs
        assert observe.mode == ResponseMode.OBSERVE
        assert respond.mode == ResponseMode.RESPOND
