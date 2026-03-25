# SRMTA Project Context & Architecture

This document serves as a foundational mandate for Gemini CLI when working on the SRMTA (Production-Grade Mail Transfer Agent) project.

## Project Overview
SRMTA is a modular, high-performance Mail Transfer Agent written in Go. It is designed for reliability, observability (Prometheus), and sophisticated outbound routing.

## Architectural Mandates

### 1. Inbound SMTP (`internal/smtp/server.go`)
- Handles incoming connections with support for STARTTLS (TLS 1.2+).
- Implements session-based processing (`session.go`) and command pipelining.
- Interfaces with `internal/access` for IP/domain-based access control (INI-based).

### 2. Queue Management (`internal/queue/manager.go`)
- Uses a multi-spool tier system: `incoming`, `active`, `deferred`, `retry`, `dead-letter`, `failed`.
- **Persistence:** Redis for fast state tracking; local disk for message bodies and metadata.
- **Scaling:** Uses consistent hashing for domain-based bucketing across shards.

### 3. Delivery Engine (`internal/delivery/engine.go`)
- Worker-based processing of the `active` queue.
- **Features:**
  - MX resolution via `internal/dns`.
  - DKIM signing via `internal/dkim`.
  - Circuit Breaker pattern for destination health management.
  - Bounce classification via `internal/bounce`.

### 4. Routing & IP Segregation (`internal/routing/router.go`)
- **Core Priority:** Protecting IP reputation through segregation.
- Supports binding sender domains or target MX patterns to dedicated IP pools.
- Fallback chains: Primary IPs → Backup IPs → Global Fallback.

### 5. Configuration (`internal/config/config.go`)
- YAML-based configuration with deep-merge support for `config.d/*.yaml`.
- Environment variable expansion is supported.

## Technical Preferences & Standards
- **Infrastructure:** Favor `systemd` for service management (units in `deploy/systemd/`).
- **Packaging:** Use `nfpm` or existing scripts for `.deb` and `.rpm` generation.
- **Utilities:**
  - Integrate **Deepspam** (custom Go utility) for inbound spam filtering.
  - Use **MXLookup** (custom Go utility) for dynamic MX routing decisions.
- **Style:** Strict adherence to idiomatic Go, comprehensive Prometheus metrics, and detailed transaction logging.

## Core Directories
- `cmd/srmta`: Main MTA daemon.
- `cmd/srmtaq`: Queue management utility.
- `internal/`: Core logic (private).
- `configs/`: Default configuration and examples.
- `deploy/`: Packaging and systemd assets.
- `migrations/`: SQL schemas for MySQL/Postgres.
