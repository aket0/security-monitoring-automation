"""Privilege escalation detection."""

from __future__ import annotations

from ..event import EventType, SecurityEvent, Severity

_HIGH_RISK_COMMANDS = frozenset({
    "sudo", "su", "pkexec", "doas",
    "chmod +s", "chown root", "setuid",
    "visudo", "passwd root",
})

_SENSITIVE_PATHS = frozenset({
    "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d",
    "/root/.ssh", "/etc/passwd",
})


class PrivilegeEscalationDetector:
    """Detect privilege escalation attempts via process or file access events."""

    def process(self, event: SecurityEvent) -> SecurityEvent | None:
        if event.event_type == EventType.SUSPICIOUS_PROCESS:
            cmd = event.metadata.get("command", "").lower()
            if any(cmd.startswith(hrc) or hrc in cmd for hrc in _HIGH_RISK_COMMANDS):
                return SecurityEvent(
                    event_type=EventType.PRIVILEGE_ESCALATION,
                    source_ip=event.source_ip,
                    username=event.username,
                    severity=Severity.CRITICAL,
                    message=f"Privilege escalation attempt detected: command '{cmd}'",
                    timestamp=event.timestamp,
                    metadata={"original_command": cmd},
                )

        if event.event_type == EventType.FILE_ACCESS_DENIED:
            path = event.metadata.get("path", "")
            if any(path.startswith(sp) for sp in _SENSITIVE_PATHS):
                return SecurityEvent(
                    event_type=EventType.PRIVILEGE_ESCALATION,
                    source_ip=event.source_ip,
                    username=event.username,
                    severity=Severity.HIGH,
                    message=f"Unauthorized access attempt to sensitive path: {path}",
                    timestamp=event.timestamp,
                    metadata={"path": path},
                )

        return None
