"""Security event model."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class EventType(StrEnum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGIN_LOCKOUT = "login_lockout"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUSPICIOUS_PROCESS = "suspicious_process"
    FILE_ACCESS_DENIED = "file_access_denied"
    NETWORK_ANOMALY = "network_anomaly"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class SecurityEvent:
    event_type: EventType
    source_ip: str
    username: str
    message: str
    severity: Severity = Severity.INFO
    timestamp: float = field(default_factory=time.time)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_log_dict(self) -> dict[str, Any]:
        """Return a structured dict for JSON logging — no passwords or tokens."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "username": self.username,
            "message": self.message,
            # metadata is included but must never contain credentials
        }
