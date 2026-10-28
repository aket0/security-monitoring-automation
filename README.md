# security-monitoring-automation

Python security monitoring system with automated, non-destructive incident response.

## Problem Solved

Security events (brute force, privilege escalation) generate noise without automated correlation, deduplication, and structured alerting. Manual response is too slow for common attack patterns. This project provides:

1. **Event detectors** with configurable thresholds (brute force, privilege escalation).
2. **Structured JSON alerting** with privacy controls (no passwords, tokens, or PII logged).
3. **Automated response** with safe-by-default principles: destructive actions always require human approval; observe mode logs only.

## Architecture

```
security-monitoring-automation/
├── src/monitoring/
│   ├── event.py              # SecurityEvent, Severity, EventType models
│   ├── engine.py             # Main pipeline: detect → alert → respond
│   ├── detectors/
│   │   ├── brute_force.py    # Sliding-window failure counter with deduplication
│   │   └── privilege_escalation.py  # Command + file access detection
│   ├── alerting/
│   │   └── logger.py         # Structured JSON logger with metadata redaction
│   └── response/
│       └── handler.py        # Observe / Respond modes, approval workflow
├── tests/                    # 33+ tests covering all components
└── .github/workflows/
    └── monitoring-ci.yml
```

## Technologies

| Component       | Technology               |
|-----------------|--------------------------|
| Language        | Python 3.11+             |
| Logging         | stdlib logging + JSON    |
| Testing         | pytest                   |
| SAST            | bandit                   |
| CI              | GitHub Actions           |

## Modes

| Mode    | Behavior                                                       |
|---------|----------------------------------------------------------------|
| OBSERVE | Log only. No actions executed. Safe for read-only environments |
| RESPOND | Safe actions execute. Destructive ones queued for approval.    |

## Prerequisites

- Python 3.11+

## Installation

```bash
git clone https://github.com/aket0/security-monitoring-automation.git
cd security-monitoring-automation
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest --cov=monitoring --cov-report=term-missing
```

Expected: all tests pass, coverage ≥ 80%.

## Quick Example

```python
from monitoring.engine import MonitoringEngine
from monitoring.event import EventType, SecurityEvent, Severity
from monitoring.detectors.brute_force import BruteForceConfig
from monitoring.response.handler import ResponseMode

engine = MonitoringEngine(
    mode=ResponseMode.OBSERVE,
    brute_force_config=BruteForceConfig(max_failures=5),
)

for _ in range(5):
    alerts = engine.process(SecurityEvent(
        event_type=EventType.LOGIN_FAILURE,
        source_ip="192.168.1.100",
        username="admin",
        message="Login failed",
    ))

print(engine.stats)
# {'events_processed': 5, 'alerts_emitted': 0, 'pending_approvals': 0}
# (alerts_emitted=0 because OBSERVE mode filters MEDIUM+ only)
```

## Security Properties

- **No credential logging**: `password`, `token`, `secret`, `session` keys are redacted before logging.
- **Non-destructive default**: OBSERVE mode never executes blocking actions.
- **Approval required**: `block_ip`, `disable_account` always require explicit approval.
- **Deduplication**: one alert per IP per time window — no alert storms.
- **No personal data collection**: only IP, username, event type, and non-sensitive metadata.

## Known Limits

- No persistent storage — state is in memory. Restart clears all windows.
- No network transport — alerts go to stdout/file, not a SIEM.
- No OpenTelemetry integration yet — planned improvement.
- No Prometheus metrics — see improvement paths.

## Improvement Paths

- Add OpenTelemetry spans and metrics.
- Persist event state to Redis for multi-instance deployments.
- Add Prometheus exporter for Grafana dashboards.
- Integrate with a SIEM (Elasticsearch, Splunk) via structured log shipping.
- Add geo-IP enrichment for source IPs.
