"""
Automated incident response handler.

SAFETY PRINCIPLES:
- All responses are non-destructive by default.
- High-impact actions (block IP, kill process) are only simulated in observe mode.
- In respond mode, only safe actions execute automatically.
  Destructive actions are logged and queued for human approval.
- No passwords, tokens, or personal data are collected.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

from ..event import EventType, SecurityEvent, Severity

logger = logging.getLogger(__name__)


class ResponseMode(StrEnum):
    OBSERVE = "observe"    # log only, no action
    RESPOND = "respond"    # safe actions execute; destructive ones queued


@dataclass
class ResponseAction:
    action_type: str
    target: str
    description: str
    executed: bool = False
    requires_approval: bool = False


@dataclass
class IncidentRecord:
    trigger_event: SecurityEvent
    actions: list[ResponseAction] = field(default_factory=list)
    mode: ResponseMode = ResponseMode.OBSERVE


class IncidentResponseHandler:
    def __init__(self, mode: ResponseMode = ResponseMode.OBSERVE) -> None:
        self._mode = mode
        self._pending_approvals: list[IncidentRecord] = []
        self._executed: list[IncidentRecord] = []
        self._on_approval_needed: list[Callable[[IncidentRecord], None]] = []

    @property
    def mode(self) -> ResponseMode:
        return self._mode

    def handle(self, event: SecurityEvent) -> IncidentRecord:
        record = IncidentRecord(trigger_event=event, mode=self._mode)

        if event.event_type == EventType.LOGIN_LOCKOUT:
            self._handle_lockout(event, record)
        elif event.event_type == EventType.PRIVILEGE_ESCALATION:
            self._handle_privilege_escalation(event, record)

        if record.actions:
            self._execute(record)

        return record

    def _handle_lockout(self, event: SecurityEvent, record: IncidentRecord) -> None:
        # Safe: log the incident
        record.actions.append(ResponseAction(
            action_type="log_incident",
            target=event.source_ip,
            description=f"Log lockout incident for {event.source_ip}",
            requires_approval=False,
        ))
        # Requires approval: block IP
        record.actions.append(ResponseAction(
            action_type="block_ip",
            target=event.source_ip,
            description=f"Block IP {event.source_ip} (requires approval)",
            requires_approval=True,
        ))

    def _handle_privilege_escalation(self, event: SecurityEvent, record: IncidentRecord) -> None:
        record.actions.append(ResponseAction(
            action_type="log_incident",
            target=event.username,
            description=f"Log privilege escalation for user {event.username}",
            requires_approval=False,
        ))
        if event.severity == Severity.CRITICAL:
            record.actions.append(ResponseAction(
                action_type="disable_account",
                target=event.username,
                description=f"Disable account {event.username} (requires approval)",
                requires_approval=True,
            ))

    def _execute(self, record: IncidentRecord) -> None:
        needs_approval = False
        for action in record.actions:
            if action.requires_approval:
                needs_approval = True
                if self._mode == ResponseMode.OBSERVE:
                    logger.info("[OBSERVE] Would execute: %s", action.description)
                else:
                    logger.warning("[RESPOND] Queued for approval: %s", action.description)
            else:
                # Safe action: execute in both modes
                logger.info("[%s] Executing: %s", self._mode.upper(), action.description)
                action.executed = True

        if needs_approval:
            self._pending_approvals.append(record)
            for cb in self._on_approval_needed:
                cb(record)
        else:
            self._executed.append(record)

    def approve(self, record: IncidentRecord) -> None:
        """Execute all pending approval actions for a record."""
        for action in record.actions:
            if action.requires_approval and not action.executed:
                logger.warning("[APPROVED] Executing: %s", action.description)
                action.executed = True
        if record in self._pending_approvals:
            self._pending_approvals.remove(record)
        self._executed.append(record)

    def on_approval_needed(self, callback: Callable[[IncidentRecord], None]) -> None:
        self._on_approval_needed.append(callback)

    @property
    def pending_approvals(self) -> list[IncidentRecord]:
        return list(self._pending_approvals)
