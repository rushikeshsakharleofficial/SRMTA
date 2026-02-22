# SRMTA — Scalable Reliable Mail Transfer Agent

Production-grade, RFC 5321/5322 compliant MTA built in Go. Designed for high-volume transactional and bulk email delivery at 100M+ emails/day.

## Features

| Category | Capabilities |
|---|---|
| **SMTP Engine** | ESMTP, STARTTLS (TLS 1.2+), AUTH (PLAIN/LOGIN), pipelining (RFC 2920), DSN |
| **Queue** | 6 spools (incoming→active→deferred→retry→dead-letter→failed), domain bucketing, sharding, crash-safe WAL journal |
| **DNS** | Async resolver with in-memory + Redis caching, MX priority, A/AAAA fallback, resolver pool |
| **IP Pool** | Health scoring (4xx/5xx/timeout/TLS), auto-disable/recovery, warm-up schedules |
| **DKIM** | Multi-key signing, relaxed canonicalization, per-domain key selection |
| **Bounce** | Hard/soft/block/policy/mailbox classification, auto-suppression, sender auto-pause |
| **Compliance** | FBL webhook ingestion, List-Unsubscribe (RFC 2369 + RFC 8058), DMARC alignment |
| **Observability** | Prometheus metrics, structured JSON logging, Grafana dashboard, CSV export |
| **Admin API** | Node.js Fastify REST API with JWT, RBAC, rate limiting, WebSocket live updates |
| **Dashboard** | Real-time queue charts, IP health view, domain stats, delivery logs |
| **Config** | Centralized YAML + `config.d/*.yaml` sub-configs, env var interpolation |

## Quick Start

### Prerequisites

- Go 1.22+
- PostgreSQL 14+
- Redis 6+
- Node.js 20+ (for Admin API)

### Build from Source

```bash
# Clone
git clone https://github.com/srmta/srmta.git
cd srmta

# Build
make build

# Run tests
make test

# Install locally (requires root)
sudo make install
```

### Install from RPM (RHEL/CentOS/Fedora/Rocky)

```bash
# Build RPM
make rpm

# Install
sudo rpm -ivh rpmbuild/RPMS/x86_64/srmta-1.0.0-1.el9.x86_64.rpm

# Or from repo (if published):
# sudo dnf install srmta
```

### Install from DEB (Debian/Ubuntu)

```bash
# Build DEB
make deb

# Install
sudo dpkg -i debbuild/srmta_1.0.0-1_amd64.deb
sudo apt-get install -f  # resolve dependencies
```

### Post-Install Setup

```bash
# 1. Edit configuration
sudo vim /etc/srmta/config.yaml
sudo vim /etc/srmta/srmta.env          # database credentials

# 2. Edit sub-configs as needed
sudo vim /etc/srmta/config.d/10-smtp.yaml
sudo vim /etc/srmta/config.d/20-dkim.yaml
sudo vim /etc/srmta/config.d/30-ips.yaml
sudo vim /etc/srmta/config.d/40-database.yaml
sudo vim /etc/srmta/config.d/50-queue.yaml

# 3. Initialize database
sudo -u postgres createuser srmta
sudo -u postgres createdb -O srmta srmta
psql -U srmta -d srmta -f /usr/share/srmta/migrations/001_init.sql

# 4. Generate DKIM keys
openssl genrsa -out /etc/srmta/dkim/example.com.key 2048
openssl rsa -in /etc/srmta/dkim/example.com.key -pubout | \
  grep -v "^---" | tr -d '\n'
# → Add resulting public key as TXT record: default._domainkey.example.com

# 5. Start services
sudo systemctl enable --now srmta.socket
sudo systemctl enable --now srmta.service

# 6. Verify
sudo systemctl status srmta
curl http://localhost:9090/metrics
```

## Directory Layout

```
/etc/srmta/
├── config.yaml            # Main configuration
├── config.d/              # Sub-configs (loaded alphabetically, merged)
│   ├── 10-smtp.yaml       # SMTP engine settings
│   ├── 20-dkim.yaml       # DKIM keys
│   ├── 30-ips.yaml        # IP pool configuration
│   ├── 40-database.yaml   # Database credentials
│   └── 50-queue.yaml      # Queue & retry policy
├── dkim/                  # DKIM private keys
│   └── example.com.key
└── srmta.env              # Secrets (env vars for systemd)

/var/spool/srmta/          # Queue spool directory
/var/log/srmta/            # Application logs
/usr/sbin/srmta            # Binary
/usr/share/srmta/migrations/  # SQL migrations
```

## Configuration

SRMTA uses a **layered configuration** system:

1. **Main config** (`/etc/srmta/config.yaml`) — base settings
2. **Sub-configs** (`/etc/srmta/config.d/*.yaml`) — merged on top, sorted alphabetically
3. **Environment variables** — expanded via `${VAR}` syntax in any YAML file

### Config Merge Rules

- Scalar values: sub-config overrides main config
- Slices: sub-config replaces the entire slice
- DKIM keys: sub-config keys are **appended** (additive)
- Use numeric prefixes (`10-`, `20-`) to control merge order

### Example: Override SMTP settings only

```yaml
# /etc/srmta/config.d/10-smtp.yaml
smtp:
  max_connections: 5000
  require_tls: true
```

## Admin API

The Node.js Fastify API runs separately:

```bash
cd api
npm install
npm start
# Listens on :3000 by default
```

Endpoints: `/api/auth/*`, `/api/send`, `/api/bulk`, `/api/schedule`, `/api/status/:id`, `/api/metrics`, `/api/webhook`, `/api/logs/*`, `/api/queue/*`, `/api/ips`, `/api/domains/*`

OpenAPI spec: `api/openapi.yaml`

## Dashboard

Open `dashboard/index.html` in a browser, or serve via nginx/caddy. It connects to the Admin API on `localhost:3000` by default.

## Monitoring

### Prometheus

Scrape the metrics endpoint:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: srmta
    static_configs:
      - targets: ['mta-host:9090']
```

### Grafana

Import `grafana/dashboard.json` for 12 pre-built panels covering delivery rate, queue depth, connections, success ratio, IP health, bounces, and latency.

## Architecture

```
┌──────────────┐    ┌────────────┐    ┌───────────────┐
│  Inbound     │───▶│   Queue    │───▶│   Delivery    │
│  SMTP Server │    │  Manager   │    │   Engine      │
│  :25 / :587  │    │  (6 spools)│    │  (worker pool)│
└──────────────┘    └────────────┘    └───────┬───────┘
                                              │
                    ┌─────────────────────────┼──────────────┐
                    │                         │              │
              ┌─────▼─────┐  ┌──────────┐  ┌─▼────────┐  ┌─▼──────────┐
              │ DNS        │  │ IP Pool  │  │ DKIM     │  │ Bounce     │
              │ Resolver   │  │ (health) │  │ Signer   │  │ Classifier │
              └────────────┘  └──────────┘  └──────────┘  └────────────┘
```

## License

MIT
