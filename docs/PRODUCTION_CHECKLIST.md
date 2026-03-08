# SRMTA Production Deployment Checklist

## Pre-Deployment

### Configuration
- [ ] Set `server.hostname` to your FQDN (must match PTR record)
- [ ] Configure `smtp.allowed_domains` with your sending domains
- [ ] Set `smtp.require_auth: true` for submission port (587)
- [ ] Configure `smtp.allowed_ips_file` and `smtp.allowed_domains_file`
- [ ] Set strong `database.password` and `redis.password`
- [ ] Run config validation: `./srmta -config /etc/srmta/config.yaml -validate`

### TLS/Security
- [ ] Generate TLS certificate (RSA 2048+ or ECDSA P-256)
- [ ] Set `tls.cert_file` and `tls.key_file` paths
- [ ] Verify `tls.min_version: "1.2"` (default)
- [ ] Replace `defaultAuthValidator` with production auth backend
- [ ] Set file permissions: config `0600`, TLS keys `0400`, spool `0750`

### DNS
- [ ] Configure MX records for receiving domains
- [ ] Set PTR (rDNS) record for each sending IP
- [ ] Publish SPF TXT record: `v=spf1 ip4:<your-ip>/32 -all`
- [ ] Generate DKIM keys and publish TXT record: `default._domainkey.example.com`
- [ ] Publish DMARC record: `_dmarc.example.com TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"`

### Infrastructure
- [ ] Provision PostgreSQL 14+ with `001_init.sql` migration
- [ ] Provision Redis 7+ for queue state and DNS cache
- [ ] Create spool directory: `mkdir -p /var/spool/srmta`
- [ ] Create log directory: `mkdir -p /var/log/srmta`
- [ ] Set up systemd service (see `deploy/srmta.service`)
- [ ] Configure firewall: open ports 25 (inbound), 587 (submission), 9090 (metrics)

### IP Warm-up
- [ ] Start with low volume (100-500/day per IP)
- [ ] Set `ip_pool.ips[].warm_up: true` for new IPs
- [ ] Set conservative `max_rate` (50-100/hour initially)
- [ ] Gradually increase over 4-6 weeks

## Post-Deployment

### Monitoring
- [ ] Configure Prometheus to scrape `http://<host>:9090/metrics`
- [ ] Import Grafana dashboard from `grafana/`
- [ ] Set up alerts (see `docs/MONITORING.md`)
- [ ] Verify health check: `curl http://localhost:9090/health`
- [ ] Verify detailed health: `curl http://localhost:9090/health/full`

### Validation
- [ ] Send test email and verify delivery
- [ ] Check DKIM signature: `opendkim-testkey -d example.com -s default`
- [ ] Verify SPF: `dig TXT example.com`
- [ ] Test DMARC: send to `check-auth@verifier.port25.com`
- [ ] Run `go test -race ./...` and verify all pass

### Ongoing Operations
- [ ] Monitor bounce rate (target < 5% hard bounces)
- [ ] Monitor complaint rate (target < 0.3%)
- [ ] Rotate DKIM keys every 6-12 months
- [ ] Review suppression list monthly
- [ ] Set up PostgreSQL partition management (pg_partman or cron)
- [ ] Configure log rotation via `logging.max_size_mb` / logrotate
