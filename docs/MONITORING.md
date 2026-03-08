# SRMTA Monitoring & Alerting Guide

## Prometheus Metrics Reference

### SMTP Server
| Metric | Type | Description |
|--------|------|-------------|
| `srmta_smtp_connections_total` | counter | Total inbound connections |
| `srmta_smtp_connections_active` | gauge | Currently active connections |
| `srmta_smtp_connections_rejected` | counter | Rejected connections (rate limit, max connections) |
| `srmta_smtp_messages_accepted_total` | counter | Successfully accepted messages |
| `srmta_smtp_processing_latency_seconds` | histogram | Message processing latency |
| `srmta_smtp_message_size_bytes` | histogram | Message size distribution |

### Authentication
| Metric | Type | Description |
|--------|------|-------------|
| `srmta_auth_success_total` | counter | Successful authentications |
| `srmta_auth_failure_total` | counter | Failed authentication attempts |

### TLS
| Metric | Type | Description |
|--------|------|-------------|
| `srmta_tls_connections_total` | counter | TLS connections established |
| `srmta_tls_handshake_errors_total` | counter | TLS handshake failures |

### Queue
| Metric | Type | Description |
|--------|------|-------------|
| `srmta_queue_enqueued_total` | counter | Messages enqueued |
| `srmta_queue_completed_total` | counter | Messages delivered successfully |
| `srmta_queue_deferred_total` | counter | Messages deferred (will retry) |
| `srmta_queue_failed_total` | counter | Messages permanently failed |
| `srmta_queue_dead_letter_total` | counter | Messages moved to dead-letter |
| `srmta_queue_processing_total` | counter | Messages currently being processed |

### Delivery
| Metric | Type | Description |
|--------|------|-------------|
| `srmta_delivery_success_total` | counter | Successfully delivered messages |
| `srmta_delivery_duration_seconds` | histogram | End-to-end delivery time |

## Health Check Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Simple liveness check — returns `{"status":"healthy"}` |
| `GET /health/full` | Detailed subsystem status (SMTP, queue, delivery, auth, TLS) |
| `GET /metrics` | Prometheus exposition format metrics |

## Recommended Alerting Rules

```yaml
groups:
  - name: srmta
    rules:
      # Queue growing — delivery may be failing
      - alert: QueueBacklog
        expr: srmta_queue_enqueued_total - srmta_queue_completed_total - srmta_queue_failed_total > 10000
        for: 15m
        labels:
          severity: warning

      # High bounce rate
      - alert: HighBounceRate
        expr: rate(srmta_bounce_total[1h]) / rate(srmta_delivery_success_total[1h]) > 0.05
        for: 30m
        labels:
          severity: critical

      # Auth brute force attempt
      - alert: AuthBruteForce
        expr: rate(srmta_auth_failure_total[5m]) > 10
        for: 5m
        labels:
          severity: warning

      # TLS errors spiking
      - alert: TLSErrors
        expr: rate(srmta_tls_handshake_errors_total[5m]) > 5
        for: 10m
        labels:
          severity: warning

      # No deliveries happening
      - alert: NoDeliveries
        expr: rate(srmta_delivery_success_total[15m]) == 0
        for: 30m
        labels:
          severity: critical

      # Connections being rejected (rate limiting)
      - alert: ConnectionsRejected
        expr: rate(srmta_smtp_connections_rejected[5m]) > 50
        for: 10m
        labels:
          severity: warning
```

## Grafana Dashboard

Import the dashboard from `grafana/srmta-dashboard.json` or create panels for:

1. **Overview** — delivery success rate, queue depth, active connections
2. **Delivery Performance** — latency percentiles, throughput by domain
3. **Bounce Analysis** — bounce rate by type, suppressed recipients
4. **IP Health** — health score per IP, disabled IPs
5. **Security** — auth failures, TLS errors, rate-limited connections
