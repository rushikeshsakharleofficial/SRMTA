# SRMTA Scaling Guide

Capacity planning and scaling strategies for 5M, 20M, and 100M emails/day.

## Tier 1: 5 Million emails/day (~58 emails/sec)

### Hardware
| Component | Spec |
|---|---|
| **SRMTA Engine** | 1 server, 4 CPU, 8GB RAM, SSD |
| **PostgreSQL** | Shared or dedicated, 2 CPU, 4GB RAM |
| **Redis** | Shared, 1GB RAM |
| **Sending IPs** | 2–3 IPv4 addresses |

### Config Tuning (`config.d/10-smtp.yaml`)
```yaml
smtp:
  max_connections: 500
delivery:
  max_concurrent: 100
  per_domain_concurrency: 10
  pool_size: 20
```

### Queue (`config.d/50-queue.yaml`)
```yaml
queue:
  shard_count: 4
  domain_buckets: 64
  processing_workers: 20
```

### Sysctl
```bash
# /etc/sysctl.d/99-srmta.conf
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
```

---

## Tier 2: 20 Million emails/day (~231 emails/sec)

### Hardware
| Component | Spec |
|---|---|
| **SRMTA Engine** | 2 servers, 8 CPU, 16GB RAM each, NVMe SSD |
| **PostgreSQL** | Dedicated, 4 CPU, 16GB RAM, streaming replica |
| **Redis** | Dedicated, 4GB RAM, Redis Sentinel |
| **Sending IPs** | 8–12 IPv4, 2–4 IPv6 |

### Config Tuning
```yaml
# 10-smtp.yaml
smtp:
  max_connections: 2000
delivery:
  max_concurrent: 300
  per_domain_concurrency: 20
  pool_size: 50

# 50-queue.yaml
queue:
  shard_count: 16
  domain_buckets: 256
  processing_workers: 50
  max_queue_depth: 1000000

rate_limit:
  global_rate: 300
  per_domain_rate: 30
```

### Multi-Node Setup
Run multiple SRMTA instances behind a shared Redis + PostgreSQL:

```
                 ┌─────────┐
    ┌────────────│  Redis   │────────────┐
    │            └─────────┘            │
    ▼                                    ▼
┌────────┐                        ┌────────┐
│ SRMTA  │  ◀── shared queue ──▶  │ SRMTA  │
│ Node 1 │      state (Redis)     │ Node 2 │
└────────┘                        └────────┘
    │                                    │
    └──────────┐            ┌────────────┘
               ▼            ▼
          ┌──────────────────────┐
          │    PostgreSQL         │
          │    (primary + replica)│
          └──────────────────────┘
```

### Sysctl (aggressive)
```bash
net.core.somaxconn = 16384
net.ipv4.tcp_max_syn_backlog = 16384
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
fs.file-max = 1000000
```

### Systemd Override
```ini
# /etc/systemd/system/srmta.service.d/20m.conf
[Service]
LimitNOFILE=262144
LimitNPROC=16384
```

---

## Tier 3: 100 Million emails/day (~1,157 emails/sec)

### Hardware
| Component | Spec |
|---|---|
| **SRMTA Engine** | 5–8 servers, 16 CPU, 32GB RAM, NVMe |
| **PostgreSQL** | Citus/partitioned, 16 CPU, 64GB RAM |
| **Redis** | Redis Cluster (3+ nodes), 16GB total |
| **Sending IPs** | 32+ IPv4, 8+ IPv6 |
| **DNS** | Dedicated resolvers (Unbound) |

### Config Tuning
```yaml
# 10-smtp.yaml
smtp:
  max_connections: 5000
delivery:
  max_concurrent: 1000
  per_domain_concurrency: 50
  pool_size: 100

# 30-ips.yaml — warm up IPs in phases
ip_pool:
  health_window: "30m"
  disable_threshold: 0.25
  recovery_time: "15m"

# 50-queue.yaml
queue:
  shard_count: 64
  domain_buckets: 1024
  processing_workers: 200
  max_queue_depth: 10000000

rate_limit:
  global_rate: 1200
  per_domain_rate: 100
```

### PostgreSQL Optimization
```sql
-- Use partitioned delivery_events table (already in schema)
-- Partition by month for fast rotation
-- Archive old partitions to cold storage

-- Connection pooling via PgBouncer
-- /etc/pgbouncer/pgbouncer.ini
-- pool_mode = transaction
-- max_client_conn = 1000
-- default_pool_size = 50
```

### Redis Cluster
```bash
# 3-node Redis Cluster for queue state
redis-cli --cluster create \
  node1:6379 node2:6379 node3:6379 \
  --cluster-replicas 1
```

### Sysctl (extreme)
```bash
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 50000
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 120
fs.file-max = 10000000
vm.swappiness = 10
```

### Systemd Override
```ini
# /etc/systemd/system/srmta.service.d/100m.conf
[Service]
LimitNOFILE=1048576
LimitNPROC=65536
```

---

## IP Warm-Up Schedule

New IPs must be warmed gradually to build reputation:

| Day | Emails/hour | Daily Volume |
|-----|-------------|-------------|
| 1–2 | 50 | 1,200 |
| 3–4 | 200 | 4,800 |
| 5–7 | 500 | 12,000 |
| 8–14 | 2,000 | 48,000 |
| 15–21 | 10,000 | 240,000 |
| 22–30 | 50,000 | 1,200,000 |
| 30+ | Unlimited | Unlimited |

Configure via `config.d/30-ips.yaml`:
```yaml
ip_pool:
  ips:
    - address: "new-ip"
      warm_up: true
      max_rate: 50   # Start at 50/hr, increase manually
```

## Performance Checklist

- [ ] **Kernel tuning**: Apply sysctl settings above
- [ ] **File descriptors**: Set `LimitNOFILE` in systemd override
- [ ] **SSD/NVMe**: Queue spool must be on fast storage
- [ ] **DNS**: Use local caching resolver (Unbound) or enable Redis DNS cache
- [ ] **Connection pooling**: Enable PgBouncer for PostgreSQL
- [ ] **IP diversity**: Mix IPv4 and IPv6, spread across /24 blocks
- [ ] **DKIM**: Pre-load keys at startup (file-backed, not network)
- [ ] **Monitoring**: Set up Prometheus alerts for queue depth > threshold
- [ ] **Log rotation**: Configure journald rate limits or file-based log rotation
- [ ] **Backpressure**: Set `max_queue_depth` to prevent unbounded growth
