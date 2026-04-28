# SRMTA — Scalable Reliable Mail Transfer Agent

Production-grade, RFC 5321/5322 compliant MTA built in Go. Designed for high-volume transactional and bulk email delivery at 100M+ emails/day.

## Features

| Category | Capabilities |
|---|---|
| **SMTP Engine** | ESMTP, STARTTLS (TLS 1.2+, mandatory on handshake), AUTH (PLAIN/LOGIN/CRAM-MD5), pipelining (RFC 2920), DSN, separate inbound (:25) and submission (:587) ports |
| **Queue** | 6 spools (incoming→active→deferred→retry→dead-letter→failed), domain bucketing, sharding, crash-safe WAL journal |
| **DNS** | Async resolver with in-memory + Redis caching, MX priority, A/AAAA fallback, resolver pool |
| **IP Pool** | Health scoring (4xx/5xx/timeout/TLS), auto-disable/recovery, warm-up schedules |
| **Smart Throttle** | Per-provider speed limits (Microsoft, Google, Yahoo, Apple, Zoho, Comcast), adaptive backoff on 4xx, rolling rate windows |
| **MX-Based Routing** | Provider→dedicated IP segregation (Google, Outlook, Yahoo, Zoho get separate IPs), primary→backup→fallback chains |
| **DKIM** | Multi-key signing, relaxed canonicalization, per-domain key selection |
| **Bounce** | Hard/soft/block/policy/mailbox classification, auto-suppression, sender auto-pause |
| **Access Control** | INI-based `allowed_ips.ini` (`[ipv4]`/`[ipv6]`/`[relay]`) and `allowed_domains.ini` (`[domains]`), wildcard domains |
| **Compliance** | FBL webhook ingestion, List-Unsubscribe (RFC 2369 + RFC 8058), DMARC alignment |
| **Observability** | Prometheus metrics, structured JSON logging, Grafana dashboard, CSV export |
| **Admin API** | Node.js Fastify REST API with JWT (30m expiry), RBAC, per-endpoint rate limiting, authenticated WebSocket live updates |
| **Dashboard** | Real-time queue charts, IP health view, domain stats, delivery logs |
| **Config** | Centralized YAML + `config.d/*.yaml` sub-configs, env var interpolation |

## Security

SRMTA enforces security-by-default. The application **will not start** without required secrets configured:

| Requirement | Details |
|---|---|
| **JWT_SECRET** | Required. No default fallback. Generate with `openssl rand -hex 32` |
| **WEBHOOK_SECRET** | Required. Separate from JWT secret. Used for HMAC-SHA256 webhook verification with constant-time comparison |
| **DB_PASSWORD** | Required. No hardcoded defaults in source or config |
| **CORS** | Explicit origin allowlist via `ALLOWED_ORIGINS` env var (no wildcard) |
| **Auth** | Database-backed bcrypt authentication. No default credentials |
| **SMTP Auth** | Default validator rejects all — you must inject a real `AuthValidator` implementation |
| **TLS** | STARTTLS handshake failures abort the connection (no plaintext fallback). DB connections default to `ssl_mode: require` |
| **WebSocket** | Requires JWT authentication |
| **Rate Limiting** | Global (100/min) + stricter per-endpoint (login: 10/min) |
| **Message IDs** | Generated with `crypto.randomUUID()` / `crypto/rand` (not `Math.random`) |
| **Bulk Send** | Capped at 1,000 messages per batch |

### Required Environment Variables

```bash
# Generate and set these BEFORE first run:
export JWT_SECRET=$(openssl rand -hex 32)
export WEBHOOK_SECRET=$(openssl rand -hex 32)
export DB_PASSWORD="your-strong-database-password"
export REDIS_PASSWORD="your-redis-password"
export ALLOWED_ORIGINS="https://admin.example.com"
```

## Quick Start

### Prerequisites

- Go 1.22+
- PostgreSQL 14+
- Redis 6+
- Node.js 20+ (for Admin API)

### Build from Source

```bash
git clone https://github.com/srmta/srmta.git
cd srmta
make build
make test
sudo make install
```

### Install from RPM (RHEL/CentOS/Fedora/Rocky)

```bash
make rpm
sudo rpm -ivh rpmbuild/RPMS/x86_64/srmta-1.1.0-1.el9.x86_64.rpm
```

### Install from DEB (Debian/Ubuntu)

```bash
make deb
sudo dpkg -i debbuild/srmta_1.1.0-1_amd64.deb
sudo apt-get install -f  # resolve dependencies
```

### Post-Install Setup

```bash
# 1. Edit configuration and set required secrets
sudo vim /etc/srmta/config.yaml
sudo vim /etc/srmta/srmta.env          # REQUIRED: set JWT_SECRET, WEBHOOK_SECRET, DB_PASSWORD, REDIS_PASSWORD

# 2. Edit sub-configs as needed
sudo vim /etc/srmta/config.d/10-smtp.yaml       # SMTP ports & limits
sudo vim /etc/srmta/config.d/20-dkim.yaml       # DKIM keys
sudo vim /etc/srmta/config.d/30-ips.yaml        # IP pool
sudo vim /etc/srmta/config.d/40-database.yaml   # DB credentials
sudo vim /etc/srmta/config.d/50-queue.yaml      # Queue & retry policy
sudo vim /etc/srmta/config.d/60-throttle.yaml   # Per-provider speed limits
sudo vim /etc/srmta/config.d/70-routing.yaml    # MX-based IP routing

# 3. Edit access control INI files
sudo vim /etc/srmta/allowed_domains.ini
sudo vim /etc/srmta/allowed_ips.ini

# 4. Initialize database
sudo -u postgres createuser srmta
sudo -u postgres createdb -O srmta srmta
psql -U srmta -d srmta -f /usr/share/srmta/migrations/001_init.sql

# 5. Generate DKIM keys
openssl genrsa -out /etc/srmta/dkim/example.com.key 2048
openssl rsa -in /etc/srmta/dkim/example.com.key -pubout | \
  grep -v "^---" | tr -d '\n'
# → Add resulting public key as TXT record: default._domainkey.example.com

# 6. Start services
sudo systemctl enable --now srmta.socket
sudo systemctl enable --now srmta.service

# 7. Verify
sudo systemctl status srmta
curl http://localhost:9090/metrics
```

## Directory Layout

```
/etc/srmta/
├── config.yaml            # Main configuration
├── config.d/              # Sub-configs (loaded alphabetically, merged)
│   ├── 10-smtp.yaml       # Inbound/outbound ports, SMTP limits
│   ├── 20-dkim.yaml       # DKIM keys
│   ├── 30-ips.yaml        # IP pool configuration
│   ├── 40-database.yaml   # Database credentials
│   ├── 50-queue.yaml      # Queue & retry policy
│   ├── 60-throttle.yaml   # Per-provider speed management
│   └── 70-routing.yaml    # MX-based IP routing
├── allowed_domains.ini    # Authorized sending domains [domains]
├── allowed_ips.ini        # Authorized relay IPs [ipv4]/[ipv6]/[relay]
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
3. **INI files** (`allowed_domains.ini`, `allowed_ips.ini`) — access control lists
4. **Environment variables** — expanded via `${VAR}` syntax in any YAML file

### SMTP Ports

```yaml
# config.d/10-smtp.yaml
smtp:
  inbound_addr: ":25"       # Port for receiving mail (MX traffic)
  submission_addr: ":587"   # Port for authenticated client submission (MSA)
  outbound_port: 25         # Remote port for outbound delivery
```

### Access Control (INI files)

```ini
# /etc/srmta/allowed_domains.ini
[domains]
example.com
.example.com        ; wildcard — all subdomains

# /etc/srmta/allowed_ips.ini
[ipv4]
203.0.113.10
10.0.0.0/8          ; CIDR range

[ipv6]
2001:db8::1
2001:db8::/32

[relay]
# Trusted relay partners
```

### Smart Speed Management

Per-provider throttle rules in `config.d/60-throttle.yaml` prevent blacklisting by respecting each provider's acceptance thresholds:

| Provider | Max Conn | Per Second | Per Minute | Per Hour | Backoff |
|---|---|---|---|---|---|
| Microsoft/Outlook | 5 | 3 | 100 | 2,000 | 3x, max 10m |
| Google/Gmail | 10 | 10 | 300 | 5,000 | 2.5x, max 8m |
| Yahoo/AOL | 5 | 5 | 150 | 3,000 | 2x, max 10m |
| Apple/iCloud | 3 | 2 | 60 | 1,000 | 3x, max 15m |
| Zoho | 5 | 5 | 150 | 3,000 | 2.5x, max 10m |
| Comcast/Xfinity | 3 | 2 | 50 | 800 | 3x, max 15m |
| Default (others) | 10 | 20 | 500 | 10,000 | 2x, max 5m |

Rates automatically reduce on 4xx throttle responses and recover on success.

### Sender Domain → IP Binding

`config.d/70-routing.yaml` supports binding specific sender (FROM) domains to dedicated IPs or subnets. Sender routes take priority over MX-based routing.

```yaml
routing:
  sender_routes:
    # Exact domain — all mail FROM example.com uses these IPs
    - domain: "example.com"
      ips:
        - "203.0.113.30"
        - "203.0.113.31"
      backup_ips:
        - "203.0.113.50"

    # Wildcard — all subdomains of corp.com use IPs in this subnet
    - domain: "*.corp.com"
      subnets:
        - "10.0.1.0/24"

    # Transactional subdomain gets its own dedicated IP
    - domain: "notify.example.com"
      ips:
        - "203.0.113.40"
```

**How it works:**
1. When delivering a message, the sender domain is checked against `sender_routes` first
2. `ips` — specific IP addresses to bind to this sender domain
3. `subnets` — CIDR ranges; pool IPs falling within the subnet are selected
4. `backup_ips` — used if all primary IPs/subnets are unhealthy
5. If no sender route matches, falls through to MX-based routing below

### MX-Based IP Routing

`config.d/70-routing.yaml` segregates sending IPs per provider to isolate reputation:

```
Recipient MX lookup
    │
    ├── *.google.com         → IPs: 203.0.113.10, .11  (backup: .20)
    ├── *.outlook.com        → IPs: 203.0.113.12, .13  (backup: .21)
    ├── *.yahoodns.net       → IPs: 203.0.113.14       (backup: .22)
    ├── *.mail.icloud.com    → IPs: 203.0.113.15       (backup: .23)
    ├── *.zoho.com           → IPs: 203.0.113.19       (backup: .24)
    └── * (self-hosted/other)→ IPs: 203.0.113.16-.18   (fallback: .50-.51)
```

Self-hosted IMAP servers and unbranded mail servers fall through to the "other" pool.

## Admin API

The Node.js Fastify API runs separately:

```bash
cd web/api && npm install

# Set required environment variables first
export JWT_SECRET=$(openssl rand -hex 32)
export WEBHOOK_SECRET=$(openssl rand -hex 32)
export DB_PASSWORD="your-db-password"
export REDIS_PASSWORD="your-redis-password"
export ALLOWED_ORIGINS="https://your-admin-domain.com"

npm start
# Listens on :3000 by default
```

All routes backed by PostgreSQL. `api_users` table stores credentials (bcrypt). Routes require JWT + RBAC (`admin`/`operator`/`viewer`).

| Endpoint | Auth | Description |
|---|---|---|
| `POST /api/auth/login` | public | Returns JWT (30m expiry) |
| `GET /api/auth/me` | JWT | Current user info |
| `POST /api/send` | operator+ | Queue single message |
| `POST /api/bulk` | operator+ | Queue up to 1,000 messages |
| `POST /api/schedule` | operator+ | Schedule a message |
| `GET /api/status/:id` | operator+ | Delivery event status from DB |
| `GET /api/metrics` | operator+ | Aggregated delivery stats (last 24h) |
| `GET /api/logs` | operator+ | Paginated delivery logs (max 200/page) |
| `GET /api/logs/export` | operator+ | CSV export (max 50,000 rows) |
| `GET /api/queue/stats` | JWT | Queue spool depths |
| `GET /api/ips` | JWT | IP pool health snapshots |
| `POST /api/webhook` | HMAC | FBL/delivery status webhook |
| `GET /ws` | JWT | WebSocket live metrics feed |

OpenAPI spec: `web/api/openapi.yaml`

> **Note:** `/api/send`, `/api/bulk`, `/api/schedule` generate message IDs but Redis/SMTP enqueue integration is pending.

## Dashboard

Open `web/ui/index.html` in a browser, or serve via nginx/caddy. Automatically connects to the API at the same origin (no hardcoded URLs).

## Monitoring

### Prometheus

```yaml
scrape_configs:
  - job_name: srmta
    static_configs:
      - targets: ['mta-host:9090']
```

### Grafana

Import `grafana/dashboard.json` — 12 pre-built panels for delivery rate, queue depth, connections, success ratio, IP health, bounces, and latency.

## Architecture

```
┌──────────────┐    ┌────────────┐    ┌───────────────┐    ┌──────────────┐
│  Inbound     │───▶│   Queue    │───▶│   Throttle    │───▶│   Delivery   │
│  SMTP :25    │    │  Manager   │    │   Manager     │    │   Engine     │
│  MSA  :587   │    │  (6 spools)│    │  (per-provider│    │  (worker pool│
└──────────────┘    └────────────┘    │   speed ctrl) │    └──────┬───────┘
                                      └───────────────┘           │
                    ┌─────────────────────────┬──────────────┬─────┘
                    │                         │              │
              ┌─────▼─────┐  ┌──────────┐  ┌─▼────────┐  ┌─▼──────────┐
              │ DNS        │  │ MX-Based │  │ DKIM     │  │ Bounce     │
              │ Resolver   │  │ IP Router│  │ Signer   │  │ Classifier │
              │            │  │ (per-MX  │  │          │  │            │
              │            │  │  IP pool)│  │          │  │            │
              └────────────┘  └──────────┘  └──────────┘  └────────────┘
```

## Code Quality

SonarCloud quality gate: **A** on all axes.

| Metric | Status |
|---|---|
| Security rating | A |
| Reliability rating | A |
| Bugs | 0 |
| Vulnerabilities | 0 |
| Security hotspots | 0 |
| Code smells | ~1 (wontfix) |

Branch protection enabled on `master` — force push and deletion blocked.

## License

MIT
