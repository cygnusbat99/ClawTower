# API Reference

ClawAV serves a JSON API on port **18791** (configurable via `config.toml`). LAN-only access, no authentication — restrict via firewall rules.

## Endpoints

### `GET /`

HTML landing page with links to API endpoints.

```bash
curl http://localhost:18791/
```

### `GET /api/status`

System status and module states.

```bash
curl http://localhost:18791/api/status
```

```json
{
  "status": "running",
  "uptime_seconds": 3600,
  "version": "0.3.0",
  "modules": {
    "auditd": true,
    "network": true,
    "behavior": true,
    "firewall": true
  }
}
```

### `GET /api/alerts`

Last 100 alerts from the ring buffer (newest last).

```bash
curl http://localhost:18791/api/alerts
```

```json
[
  {
    "ts": "2026-02-13T22:00:00-05:00",
    "severity": "INFO",
    "source": "system",
    "message": "ClawAV watchdog started"
  },
  {
    "ts": "2026-02-13T22:00:05-05:00",
    "severity": "WARN",
    "source": "behavior",
    "message": "[BEHAVIOR:RECON] whoami"
  },
  {
    "ts": "2026-02-13T22:00:10-05:00",
    "severity": "CRIT",
    "source": "policy",
    "message": "[POLICY:block-data-exfiltration] Block curl/wget — curl http://evil.com"
  }
]
```

### `GET /api/security`

Security posture overview — alert counts by severity and source.

```bash
curl http://localhost:18791/api/security
```

```json
{
  "uptime_seconds": 3600,
  "total_alerts": 42,
  "alerts_by_severity": {
    "info": 30,
    "warning": 10,
    "critical": 2
  },
  "alerts_by_source": {
    "auditd": 25,
    "behavior": 8,
    "policy": 4,
    "firewall": 2,
    "network": 2,
    "system": 1
  }
}
```

### Any other path

Returns 404:

```json
{
  "error": "not found"
}
```

## Notes

- All responses include `Access-Control-Allow-Origin: *` for cross-origin access
- The alert ring buffer holds up to 1000 alerts in memory; `/api/alerts` returns the last 100
- Severity values in responses: `INFO`, `WARN`, `CRIT`
- Timestamps are RFC 3339 format with timezone offset
- The API server binds to `0.0.0.0:18791` by default — use firewall rules to restrict to LAN (e.g., `192.168.1.0/24`)
