# Operations Deployment Guide

This guide provides step-by-step instructions for deploying runtime-guard in production
environments. It covers installation, systemd service setup, logging integration,
metrics export, and troubleshooting.

**Target audience:** DevOps, SRE, and ops teams deploying runtime-guard across
Python data pipelines and ML workflows.

---

## Table of Contents

1. [Installation](#installation)
2. [Systemd Service Setup](#systemd-service-setup)
3. [Logging Integration](#logging-integration)
4. [Metrics Export](#metrics-export)
5. [Dynamic Policy Reloading](#dynamic-policy-reloading)
6. [Troubleshooting](#troubleshooting)
7. [Performance & Resource Impact](#performance--resource-impact)
8. [Rollback & Recovery](#rollback--recovery)

---

## Installation

### Python package installation

For a virtual environment in a repository:

```bash
# Clone or navigate to your repo
cd /path/to/your-repo

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install runtime-guard
pip install git+https://github.com/tom-stening/runtime-guard.git

# Verify installation
runtime-guard --version
python -c "from runtime_guard import RuntimeGuard; print('✓ Import OK')"
```

### System-wide installation (shared across multiple repos)

```bash
# Install to /opt/runtime-guard
sudo mkdir -p /opt/runtime-guard
cd /opt/runtime-guard
sudo python3 -m venv venv
sudo ./venv/bin/pip install git+https://github.com/tom-stening/runtime-guard.git

# Create wrapper script for system access
sudo tee /usr/local/bin/runtime-guard > /dev/null <<'EOF'
#!/bin/bash
/opt/runtime-guard/venv/bin/python -m runtime_guard "$@"
EOF
sudo chmod +x /usr/local/bin/runtime-guard
```

### Verify cross-platform support

```bash
# Check which OS snapshot is available
runtime-guard --snapshot

# Should show:
# - Linux: /proc/meminfo parsing (most detail)
# - macOS: vm_stat output (disk/swap info)
# - Windows: PowerShell Get-CimInstance with wmic fallback
```

---

## Systemd Service Setup

### For a single repository

1. **Create environment file** (`/etc/runtime-guard/my-repo.env`):

```bash
sudo mkdir -p /etc/runtime-guard
sudo tee /etc/runtime-guard/my-repo.env > /dev/null <<'EOF'
# Repository paths
REPO_PATH=/path/to/my-repo
PYTHON_BIN=/path/to/my-repo/.venv/bin/python
WATCHER_SCRIPT=/path/to/my-repo/scripts/runtime_guard_repo_watcher.py

# Monitoring configuration
RUNTIME_GUARD_POSTURE=relaxed
RUNTIME_GUARD_COOLDOWN_S=30
RUNTIME_GUARD_STAGE=repo-monitor

# Logging
LOG_FILE=/var/log/runtime-guard/my-repo.log
LOG_LEVEL=INFO

# Optional: auto-recovery settings
RUNTIME_GUARD_ENABLE_SIGNAL_RECOVERY=true
RUNTIME_GUARD_AUTO_INTERVENE=true
EOF
sudo chmod 600 /etc/runtime-guard/my-repo.env
```

2. **Install systemd user service** (if running as non-root):

```bash
# For user systemd instance
mkdir -p ~/.config/systemd/user
cp scripts/systemd/runtime-guard-repo@.service ~/.config/systemd/user/

# Enable and start
systemctl --user daemon-reload
systemctl --user enable runtime-guard-repo@my-repo.service
systemctl --user start runtime-guard-repo@my-repo.service

# Check status
systemctl --user status runtime-guard-repo@my-repo.service

# View logs
journalctl --user -u "runtime-guard-repo@my-repo.service" -f
```

3. **Or install as system service** (requires root):

```bash
# For system-wide deployment
sudo cp scripts/systemd/runtime-guard-repo@.service /etc/systemd/system/

# Start service
sudo systemctl daemon-reload
sudo systemctl enable runtime-guard-repo@my-repo.service
sudo systemctl start runtime-guard-repo@my-repo.service

# View logs
sudo journalctl -u "runtime-guard-repo@my-repo.service" -f
```

### For multiple repositories

Use the `@` instance syntax to deploy one service per repo:

```bash
# Start service for repo1
sudo systemctl start runtime-guard-repo@repo1.service

# Start service for repo2
sudo systemctl start runtime-guard-repo@repo2.service

# View all runtime-guard services
systemctl list-units "runtime-guard-repo@*.service"

# View logs from all instances
journalctl -u "runtime-guard-repo@*.service" -f
```

Each service reads its own config from `/etc/runtime-guard/<instance-name>.env`.

---

## Logging Integration

### Structured event format

runtime-guard emits structured JSON events on the `runtime_guard.events` logger:

```python
import logging
logging.getLogger("runtime_guard.events").info(
    json.dumps({
        "timestamp": "2026-05-10T10:23:45Z",
        "stage": "data-load",
        "is_critical": False,
        "cause": "Low available RAM (self-inflicted)",
        "self_inflicted": True,
        "missing_mem_mb": 512,
        "pid": 12345,
    })
)
```

### Configure Python logging to capture events

Create or update your application's logging config:

```python
# logging_config.py
import logging.config

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "format": '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}',
        },
        "standard": {
            "format": "[%(levelname)s] %(name)s: %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
            "stream": "ext://sys.stderr",
        },
        "file_events": {
            "class": "logging.FileHandler",
            "formatter": "json",
            "filename": "/var/log/runtime-guard/events.json",
            "mode": "a",
        },
    },
    "loggers": {
        "runtime_guard.events": {
            "handlers": ["console", "file_events"],
            "level": "INFO",
            "propagate": False,
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
}

logging.config.dictConfig(LOGGING_CONFIG)
```

### Centralized log aggregation (ELK/DataDog/New Relic)

Forward runtime_guard events to your observability platform:

```python
# Configure JSON file output for log shipper
handlers = {
    "file": {
        "class": "logging.handlers.RotatingFileHandler",
        "filename": "/var/log/runtime-guard/events.jsonl",
        "maxBytes": 100_000_000,  # 100 MB
        "backupCount": 10,
        "formatter": "json",
    },
}

# Use filebeat/logstash/fluentd to ship to central logger
# Example filebeat config:
# - type: log
#   enabled: true
#   paths:
#     - /var/log/runtime-guard/events.jsonl
#   json.message_key: message
#   json.keys_under_root: true
#   json.add_error_key: true
```

### Real-time monitoring with `tail`

```bash
# Watch runtime-guard events in real time
tail -f /var/log/runtime-guard/events.json | jq '.'

# Filter for critical events only
tail -f /var/log/runtime-guard/events.json | jq 'select(.is_critical == true)'

# Count events by stage
tail -f /var/log/runtime-guard/events.json | jq -s 'group_by(.stage) | map({stage: .[0].stage, count: length})'
```

---

## Metrics Export

### Prometheus metrics

Export runtime-guard pressure reports as Prometheus metrics:

```python
from runtime_guard import RuntimeGuard, render_prometheus_metrics
import http.server
import socketserver

guard = RuntimeGuard()

class MetricsHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            report = guard.check(stage="app-check")
            if report:
                metrics = render_prometheus_metrics(report, prefix="runtime_guard")
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(metrics.encode())
            else:
                # No pressure detected
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"# runtime_guard: no pressure\n")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress log spam

if __name__ == "__main__":
    with socketserver.TCPServer(("0.0.0.0", 8000), MetricsHandler) as httpd:
        print("Prometheus metrics server on http://0.0.0.0:8000/metrics")
        httpd.serve_forever()
```

Add to Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: "runtime-guard"
    static_configs:
      - targets: ["localhost:8000"]
    scrape_interval: 30s
```

### OpenTelemetry span events

Export pressure reports as OTEL span events:

```python
from runtime_guard import RuntimeGuard, emit_otel_event
from opentelemetry import trace

tracer = trace.get_tracer(__name__)
guard = RuntimeGuard()

with tracer.start_as_current_span("data-processing") as span:
    report = guard.check(stage="processing")
    if report:
        emit_otel_event(report, event_name="runtime_guard.pressure", span=span)
        # Continue with mitigation...
```

---

## Dynamic Policy Reloading

runtime-guard can load threshold and posture overrides from a JSON policy file
and automatically refresh them when the file changes on disk. This allows ops
teams to tighten or relax thresholds without restarting the monitored process.

### Supported flow

```python
from runtime_guard import RuntimeGuard

guard = RuntimeGuard()
guard.load_policy_file("/etc/runtime-guard/policy.json", auto_reload=True)

# Each check() call will reload automatically when the file mtime changes.
guard.check_and_log(stage="background")
```

### Example policy file

```json
{
    "posture": "relaxed",
    "min_mem_available_mb": 1536,
    "critical_mem_mb": 768,
    "max_swap_used_pct": 90,
    "critical_swap_pct": 97,
    "self_inflicted_pct": 20
}
```

### Precedence rules

Threshold resolution uses the following order:

1. Environment variables
2. Loaded policy file / in-memory policy overrides
3. Built-in preset posture defaults

This means emergency overrides can still be applied immediately with
environment variables, even when policy-file reloading is enabled.

### Operational rollout pattern

1. Create a policy file in a stable location such as
     `/etc/runtime-guard/policy.json`.
2. Load it once during process startup with `load_policy_file(..., auto_reload=True)`.
3. Update the file atomically during incidents:

```bash
cat > /tmp/runtime-guard-policy.json <<'EOF'
{
    "posture": "ci",
    "min_mem_available_mb": 1024,
    "critical_mem_mb": 512
}
EOF
mv /tmp/runtime-guard-policy.json /etc/runtime-guard/policy.json
```

4. The next `check()` or `check_and_log()` call reloads the file automatically.

### Manual validation

```bash
python - <<'EOF'
from runtime_guard import RuntimeGuard

guard = RuntimeGuard()
before = guard.load_policy_file("/etc/runtime-guard/policy.json", auto_reload=True)
print("Loaded:", before)
print("Reloaded?", guard.reload_policy_if_changed())
EOF
```

### Failure modes

| Failure mode | Behavior | Operator action |
|---|---|---|
| Policy file missing after startup | Reload is skipped and current policy remains active | Restore the file at the configured path |
| Invalid JSON | Reload raises `ValueError` on the next reload attempt | Validate JSON before replacing the live file |
| Invalid config values | Reload raises validation error and existing policy remains in memory | Fix the bad values and rewrite atomically |
| File updated without mtime change | Reload may not trigger on that check cycle | Use atomic replace (`mv`) rather than in-place edits |

### Recommendation

Prefer atomic file replacement over editing the file in place. It gives a clean
mtime change, avoids partial writes, and makes rollback trivial.

---

## Troubleshooting

### Check if service is running

```bash
# User service
systemctl --user status runtime-guard-repo@my-repo.service

# System service
sudo systemctl status runtime-guard-repo@my-repo.service

# All instances
systemctl list-units "runtime-guard-repo@*.service" --all
```

### View service logs

```bash
# Last 50 lines
journalctl --user -u "runtime-guard-repo@my-repo.service" -n 50

# Follow in real time
journalctl --user -u "runtime-guard-repo@my-repo.service" -f

# Filter by level
journalctl --user -u "runtime-guard-repo@my-repo.service" -p err

# Between specific times
journalctl --user -u "runtime-guard-repo@my-repo.service" \
  --since "2026-05-10 10:00:00" \
  --until "2026-05-10 11:00:00"
```

### Verify configuration

```bash
# Check environment file
cat /etc/runtime-guard/my-repo.env

# Check systemd unit
systemctl --user cat runtime-guard-repo@my-repo.service

# Run manual check with same config
source /etc/runtime-guard/my-repo.env
${PYTHON_BIN} -c "
import sys; sys.path.insert(0, '${REPO_PATH}')
from runtime_guard import RuntimeGuard
g = RuntimeGuard(env_prefix='RUNTIME_GUARD')
report = g.check(stage='manual-check')
print(f'Memory: {report.snapshot.mem_available_mb}MB available')
"
```

### Common issues

| Issue | Diagnosis | Fix |
|---|---|---|
| Service won't start | `systemctl status` shows error | Check env file syntax: `source /etc/runtime-guard/my-repo.env` without errors |
| No logs in journalctl | Service may not be logging correctly | Verify logger setup; check `/var/log/runtime-guard/` permissions |
| Events not emitted | Guard not detecting pressure | Verify thresholds: `RUNTIME_GUARD_MIN_MEM_AVAILABLE_MB`, `RUNTIME_GUARD_POSTURE` |
| Permission denied on log file | Log directory not writable | `sudo chmod 777 /var/log/runtime-guard/` |
| Service crashes after startup | Python import error | Check: `${PYTHON_BIN} -c "import runtime_guard; print('OK')"` |

### Manual diagnostics

```bash
# Check memory state directly
runtime-guard --snapshot

# Run a full system report
runtime-guard --report

# Test with CI thresholds
runtime-guard --check --posture ci --stage "diagnostic"

# Verify log output
export RUNTIME_GUARD_POSTURE=tight
python -c "from runtime_guard import RuntimeGuard; g = RuntimeGuard(); g.check_and_log(stage='test')"
```

---

## Performance & Resource Impact

### Overhead assessment

runtime-guard is designed for minimal overhead:

- **Memory:** ~10 MB resident (small stdlib + core logic)
- **CPU:** ~1-5ms per check (memory read from `/proc`, no computation)
- **Background thread:** ~0.1% CPU when idle (polling every 10 seconds)
- **No dependencies:** Zero impact from dependency conflicts

### Baseline test

Run this before and after deploying runtime-guard:

```python
import time
from runtime_guard import RuntimeGuard

guard = RuntimeGuard()

# Warm up
for _ in range(10):
    guard.check()

# Benchmark: 1000 checks
start = time.perf_counter()
for _ in range(1000):
    guard.check(stage="benchmark")
elapsed = time.perf_counter() - start

avg_ms = (elapsed / 1000) * 1000
print(f"Average check time: {avg_ms:.3f} ms per call")
print(f"Total for 1000 calls: {elapsed:.2f} seconds")

# Expected: <5ms per call on any modern system
assert avg_ms < 5, f"Performance regression detected: {avg_ms}ms > 5ms"
```

### Scaling to many processes

For environments with hundreds of processes (e.g., Kubernetes cluster):

1. **Use cooldown to reduce logging:**

```bash
export RUNTIME_GUARD_COOLDOWN_S=60  # Suppress duplicate logs within 60s
```

2. **Filter logs on emission level:**

```bash
export RUNTIME_GUARD_LOG_LEVEL=WARNING  # Only log WARNING and above
```

3. **Aggregate metrics centrally:**

Collect `/metrics` from all instances to Prometheus, then query for patterns.

---

## Rollback & Recovery

### Disable without uninstalling

```bash
# Stop the service
sudo systemctl stop runtime-guard-repo@my-repo.service

# Disable auto-start
sudo systemctl disable runtime-guard-repo@my-repo.service

# Verify
sudo systemctl status runtime-guard-repo@my-repo.service
```

### Uninstall completely

```bash
# Stop and disable
sudo systemctl stop runtime-guard-repo@my-repo.service
sudo systemctl disable runtime-guard-repo@my-repo.service

# Remove systemd unit
sudo rm /etc/systemd/system/runtime-guard-repo@.service
sudo systemctl daemon-reload

# Remove configuration
sudo rm -rf /etc/runtime-guard

# Uninstall package
pip uninstall runtime-guard

# Remove logs (optional)
sudo rm -rf /var/log/runtime-guard
```

### Recover from configuration error

If the service crashes due to bad config:

1. Edit environment file:

```bash
sudo nano /etc/runtime-guard/my-repo.env
```

2. Fix the issue (e.g., syntax error, bad path)

3. Restart service:

```bash
sudo systemctl restart runtime-guard-repo@my-repo.service
```

### Test config changes before restarting

```bash
# Source the environment
source /etc/runtime-guard/my-repo.env

# Verify Python can run with new config
${PYTHON_BIN} << 'EOF'
import os
from runtime_guard import RuntimeGuard
g = RuntimeGuard()
report = g.check(stage='config-test')
print(f"✓ Config OK: {report.snapshot.mem_available_mb}MB available")
EOF

# If OK, restart service
sudo systemctl restart runtime-guard-repo@my-repo.service
```

---

## Next Steps

- **Monitor adoption:** Track metrics using `build_adoption_scorecard()` API
- **Refine thresholds:** Adjust `RUNTIME_GUARD_POSTURE` based on real pressure patterns
- **Integrate with alerting:** Use metric export to feed Prometheus/Grafana/DataDog alerts
- **Plan remediation:** Set up runbooks for teams when pressure incidents occur (see `ENTERPRISE_SUPPORT.md`)
