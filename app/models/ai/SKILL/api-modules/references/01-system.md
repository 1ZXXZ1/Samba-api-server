# System Endpoints — AI Skill Reference

> Module: `system` | Router: `app/routers/system.py` | Version: api_v1.9.6-7

## Overview

Provides system-level monitoring and diagnostics for the Samba AD DC server. Includes health checks, Prometheus-compatible metrics, and real-time system statistics. These endpoints are typically used for monitoring dashboards and alerting systems.

## Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/v1/system/health` | `system.health` | Basic health check — returns OK if the API is responsive |
| GET | `/api/v1/system/health/detailed` | `system.health` | Detailed health check — includes AD DC service status, connectivity |
| GET | `/api/v1/system/metrics` | `system.metrics` | Prometheus-format metrics for monitoring |
| GET | `/api/v1/system/stats` | `system.stats` | System statistics — CPU, memory, uptime, Samba process info |

## Key Parameters

| Parameter | Type | Used In | Description |
|-----------|------|---------|-------------|
| `format` | string | `/metrics` | Output format: `prometheus` (default) or `json` |

## Usage Examples

```bash
# Basic health check
curl -s -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/system/health

# Detailed health with service status
curl -s -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/system/health/detailed

# Get system statistics
curl -s -H "Authorization: Bearer $TOKEN" \
  https://dc.example.com/api/v1/system/stats
```

## Batch Methods

Not available in batch operations.

## Notes

- Health endpoints are lightweight and safe to poll frequently (every 10–30 seconds).
- Prometheus metrics endpoint is designed for scrape-based monitoring (Prometheus, VictoriaMetrics, etc.).
- `system.stats` may require elevated permissions depending on deployment configuration.
- The `detailed` health check performs actual AD connectivity tests and may take longer than the basic check.
