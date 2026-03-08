-- SRMTA PostgreSQL Schema
-- Partitioned tables for high-volume event logging (100M+ emails/day)

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ============================================================================
-- Core Tables
-- ============================================================================

-- Delivery events — partitioned by month for 100M/day scale
CREATE TABLE delivery_events (
    id              BIGSERIAL,
    timestamp       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    message_id      VARCHAR(128)  NOT NULL,
    sender          VARCHAR(512)  NOT NULL,
    recipient       VARCHAR(512)  NOT NULL,
    remote_mx       VARCHAR(256),
    response_code   SMALLINT,
    response_text   TEXT,
    ip_used         INET,
    tls_status      BOOLEAN       DEFAULT FALSE,
    retry_count     SMALLINT      DEFAULT 0,
    dkim_status     VARCHAR(32),
    processing_latency_ms BIGINT,
    status          VARCHAR(32)   NOT NULL, -- delivered, deferred, bounced, failed
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Create partitions for the next 12 months
-- In production, use pg_partman or a cron job to create partitions automatically
CREATE TABLE delivery_events_2026_01 PARTITION OF delivery_events
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE delivery_events_2026_02 PARTITION OF delivery_events
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE delivery_events_2026_03 PARTITION OF delivery_events
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
CREATE TABLE delivery_events_2026_04 PARTITION OF delivery_events
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE delivery_events_2026_05 PARTITION OF delivery_events
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE delivery_events_2026_06 PARTITION OF delivery_events
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
CREATE TABLE delivery_events_2026_07 PARTITION OF delivery_events
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE delivery_events_2026_08 PARTITION OF delivery_events
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE delivery_events_2026_09 PARTITION OF delivery_events
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE delivery_events_2026_10 PARTITION OF delivery_events
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE delivery_events_2026_11 PARTITION OF delivery_events
    FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE delivery_events_2026_12 PARTITION OF delivery_events
    FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');

-- Indexes for delivery events
CREATE INDEX idx_events_message_id ON delivery_events (message_id);
CREATE INDEX idx_events_sender ON delivery_events (sender);
CREATE INDEX idx_events_recipient ON delivery_events (recipient);
CREATE INDEX idx_events_status ON delivery_events (status, timestamp);
CREATE INDEX idx_events_domain ON delivery_events (
    SUBSTRING(recipient FROM POSITION('@' IN recipient) + 1)
);

-- ============================================================================
-- Bounce Records
-- ============================================================================
CREATE TABLE bounces (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    message_id      VARCHAR(128)  NOT NULL,
    sender          VARCHAR(512)  NOT NULL,
    recipient       VARCHAR(512)  NOT NULL,
    bounce_type     VARCHAR(32)   NOT NULL, -- hard, soft, block, policy, mailbox_full
    response_code   SMALLINT,
    response_text   TEXT,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_bounces_sender ON bounces (sender, timestamp);
CREATE INDEX idx_bounces_recipient ON bounces (recipient);
CREATE INDEX idx_bounces_type ON bounces (bounce_type, timestamp);

-- ============================================================================
-- Suppression List
-- ============================================================================
CREATE TABLE suppression_list (
    id              BIGSERIAL PRIMARY KEY,
    email           VARCHAR(512)  NOT NULL UNIQUE,
    reason          VARCHAR(64)   NOT NULL, -- hard_bounce, complaint, manual
    source_message  VARCHAR(128),
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_suppression_email ON suppression_list (email);

-- ============================================================================
-- Complaints (FBL)
-- ============================================================================
CREATE TABLE complaints (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    message_id      VARCHAR(128),
    sender          VARCHAR(512)  NOT NULL,
    recipient       VARCHAR(512)  NOT NULL,
    feedback_type   VARCHAR(32),  -- abuse, fraud, not-spam
    source          VARCHAR(128), -- ISP/provider
    raw_arf         TEXT,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_complaints_sender ON complaints (sender, timestamp);
CREATE INDEX idx_complaints_recipient ON complaints (recipient);

-- ============================================================================
-- Sender Statistics
-- ============================================================================
CREATE TABLE sender_stats (
    id              BIGSERIAL PRIMARY KEY,
    sender          VARCHAR(512)  NOT NULL UNIQUE,
    total_sent      BIGINT        DEFAULT 0,
    delivered       BIGINT        DEFAULT 0,
    hard_bounces    BIGINT        DEFAULT 0,
    soft_bounces    BIGINT        DEFAULT 0,
    complaints      BIGINT        DEFAULT 0,
    bounce_rate     DECIMAL(5,4)  DEFAULT 0,
    complaint_rate  DECIMAL(5,4)  DEFAULT 0,
    paused          BOOLEAN       DEFAULT FALSE,
    paused_at       TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sender_stats_sender ON sender_stats (sender);

-- ============================================================================
-- IP Health Log
-- ============================================================================
CREATE TABLE ip_health_log (
    id              BIGSERIAL PRIMARY KEY,
    ip_address      INET          NOT NULL,
    health_score    DECIMAL(3,2)  NOT NULL,
    total_sent      BIGINT        DEFAULT 0,
    rate_4xx        DECIMAL(5,4)  DEFAULT 0,
    rate_5xx        DECIMAL(5,4)  DEFAULT 0,
    timeout_rate    DECIMAL(5,4)  DEFAULT 0,
    tls_fail_rate   DECIMAL(5,4)  DEFAULT 0,
    disabled        BOOLEAN       DEFAULT FALSE,
    recorded_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ip_health_ip ON ip_health_log (ip_address, recorded_at);

-- ============================================================================
-- Domain Delivery Statistics
-- ============================================================================
CREATE TABLE domain_stats (
    id              BIGSERIAL PRIMARY KEY,
    domain          VARCHAR(256)  NOT NULL,
    date            DATE          NOT NULL,
    total_sent      BIGINT        DEFAULT 0,
    delivered       BIGINT        DEFAULT 0,
    bounced         BIGINT        DEFAULT 0,
    deferred        BIGINT        DEFAULT 0,
    complaints      BIGINT        DEFAULT 0,
    avg_latency_ms  BIGINT        DEFAULT 0,
    UNIQUE(domain, date)
);

CREATE INDEX idx_domain_stats_domain ON domain_stats (domain, date);

-- ============================================================================
-- API Users (for admin dashboard)
-- ============================================================================
CREATE TABLE api_users (
    id              UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    username        VARCHAR(128)  NOT NULL UNIQUE,
    password_hash   VARCHAR(256)  NOT NULL,
    role            VARCHAR(32)   NOT NULL DEFAULT 'viewer', -- admin, operator, viewer
    api_key         VARCHAR(128)  UNIQUE,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    last_login      TIMESTAMPTZ
);

-- ============================================================================
-- Audit Log
-- ============================================================================
CREATE TABLE audit_log (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    user_id         UUID          REFERENCES api_users(id),
    action          VARCHAR(128)  NOT NULL,
    resource        VARCHAR(256),
    details         JSONB,
    ip_address      INET
);

CREATE INDEX idx_audit_timestamp ON audit_log (timestamp);
CREATE INDEX idx_audit_user ON audit_log (user_id);

-- ============================================================================
-- Retention Policy
-- ============================================================================
-- Run this periodically (e.g., via pg_cron) to drop old partitions
-- DROP TABLE IF EXISTS delivery_events_YYYY_MM;
-- Recommended retention: 90 days for events, 365 days for bounces/complaints
