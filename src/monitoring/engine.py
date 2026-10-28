"""Main monitoring engine: ties collectors, detectors, alerting, and response together."""

from __future__ import annotations

import io

from .alerting.logger import AlertLogger
from .detectors.brute_force import BruteForceConfig, BruteForceDetector
from .detectors.privilege_escalation import PrivilegeEscalationDetector
from .event import SecurityEvent, Severity
from .response.handler import IncidentResponseHandler, ResponseMode


class MonitoringEngine:
    """
    Processes security events through the full pipeline:
    event → detector → alert → response.
    """

    def __init__(
        self,
        mode: ResponseMode = ResponseMode.OBSERVE,
        brute_force_config: BruteForceConfig | None = None,
        min_alert_severity: Severity = Severity.MEDIUM,
        alert_stream: io.IOBase | None = None,
    ) -> None:
        self._bf_detector = BruteForceDetector(brute_force_config)
        self._pe_detector = PrivilegeEscalationDetector()
        self._alert_logger = AlertLogger(stream=alert_stream, min_severity=min_alert_severity)
        self._responder = IncidentResponseHandler(mode=mode)
        self._processed: int = 0
        self._alerts_emitted: int = 0

    def process(self, event: SecurityEvent) -> list[SecurityEvent]:
        """Process one event. Returns any alert events generated."""
        self._processed += 1
        alerts: list[SecurityEvent] = []

        for alert in filter(None, [
            self._bf_detector.process(event),
            self._pe_detector.process(event),
        ]):
            alerts.append(alert)
            if self._alert_logger.emit(alert):
                self._alerts_emitted += 1
            self._responder.handle(alert)

        return alerts

    @property
    def stats(self) -> dict:
        return {
            "events_processed": self._processed,
            "alerts_emitted": self._alerts_emitted,
            "pending_approvals": len(self._responder.pending_approvals),
        }

    @property
    def responder(self) -> IncidentResponseHandler:
        return self._responder
