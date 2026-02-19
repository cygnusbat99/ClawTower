# API Reference

ClawTower serves a JSON API on port **18791** (configurable via `config.toml`).
By default it binds to `127.0.0.1`.

Authentication is optional:

- If `[api].auth_token` is empty, endpoints are unauthenticated.
- If `[api].auth_token` is set, requests must include `Authorization: Bearer <token>`.
- `GET /api/health` remains unauthenticated for health checks.

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

With bearer auth enabled:

```bash
curl -H "Authorization: Bearer $CLAWTOWER_API_TOKEN" http://localhost:18791/api/status
```

```json
{
  "status": "running",
  "uptime_seconds": 3600,
  "version": "0.5.0-beta",
  "parity": {
    "mismatches_total": 0,
    "alerts_emitted": 0,
    "alerts_suppressed": 0
  },
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
    "message": "ClawTower watchdog started"
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
  "parity": {
    "mismatches_total": 0,
    "alerts_emitted": 0,
    "alerts_suppressed": 0
  },
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

### `GET /api/health`

Health check with last alert age and version info.

```bash
curl http://localhost:18791/api/health
```

```json
{
  "healthy": true,
  "uptime_seconds": 3600,
  "version": "0.5.0-beta",
  "last_alert_age_seconds": 45
}
```

- `version` is the Cargo package version (`CARGO_PKG_VERSION`)
- `last_alert_age_seconds` is `null` if no alerts have been received

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
- `parity.*` counters are primarily useful when `[behavior].detector_shadow_mode = true`
- If auth is enabled and the bearer token is missing/invalid, endpoints (except `/api/health`) return `401` with `{"error":"unauthorized"}`
- Severity values in responses: `INFO`, `WARN`, `CRIT`
- Timestamps are RFC 3339 format with timezone offset
- Default bind is `127.0.0.1:18791`; set `[api].bind = "0.0.0.0"` to expose on LAN and restrict access with firewall rules

## See Also

- [CONFIGURATION.md](CONFIGURATION.md) — Full `[api]` config reference
- [ALERT-PIPELINE.md](ALERT-PIPELINE.md) — How alerts flow from sources to the API store
- [ARCHITECTURE.md](ARCHITECTURE.md) — Module dependency graph and data flow
