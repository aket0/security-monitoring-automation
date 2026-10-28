"""Structured JSON alert logger."""

from __future__ import annotations

import json
import logging
import sys
from typing import IO

from ..event import SecurityEvent, Severity


def _make_logger(name: str, stream: IO) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    return logger


class AlertLogger:
    """
    Emit structured JSON log lines for security alerts.

    Privacy: never log passwords, tokens, or session cookies.
    Sensitive fields in metadata are redacted before logging.
    """

    _REDACTED_KEYS = frozenset({
        "password", "passwd", "token", "secret", "api_key",
        "session", "cookie", "authorization",
    })

    def __init__(self, stream: IO | None = None, min_severity: Severity = Severity.INFO) -> None:
        self._stream = stream or sys.stdout
        self._min_severity = min_severity
        self._logger = _make_logger(f"security.alerts.{id(self)}", self._stream)
        self._order = list(Severity)

    def _severity_index(self, sev: Severity) -> int:
        return self._order.index(sev)

    def _redact_metadata(self, metadata: dict) -> dict:
        return {
            k: "[REDACTED]" if k.lower() in self._REDACTED_KEYS else v
            for k, v in metadata.items()
        }

    def emit(self, event: SecurityEvent) -> bool:
        """Log the event. Returns True if emitted, False if filtered by severity."""
        if self._severity_index(event.severity) > self._severity_index(self._min_severity):
            return False
        log_dict = event.to_log_dict()
        if event.metadata:
            log_dict["metadata"] = self._redact_metadata(event.metadata)
        self._logger.info(json.dumps(log_dict, default=str))
        return True
