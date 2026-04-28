-- SRMTA MySQL/MariaDB Schema
-- Equivalent of the PostgreSQL schema for MySQL/MariaDB 8.0+ environments.
-- All PostgreSQL-specific types mapped to MySQL equivalents:
--   BIGSERIAL      → BIGINT AUTO_INCREMENT
--   TIMESTAMPTZ    → DATETIME(6) (microsecond precision)
--   INET           → VARCHAR(45) (supports IPv6 + scope)
--   JSONB          → JSON
--   UUID           → CHAR(36)
--   DECIMAL(5,4)   → DECIMAL(5,4) (same)
--   BOOLEAN        → TINYINT(1)
--   TEXT           → TEXT (same)
--
-- Note: MariaDB 10.5+ also supports these types natively.

-- ============================================================================
-- Core Settings
-- ============================================================================
SET NAMES utf8mb4;
SET CHARACTER SET utf8mb4;
SET collation_connection = 'utf8mb4_unicode_ci';

-- ============================================================================
-- Delivery Events
-- ============================================================================
-- Note: MySQL 8.0+ supports PARTITION BY RANGE on DATE/DATETIME columns.
-- For MariaDB or MySQL < 8.0, remove the PARTITION clause and use separate tables.
CREATE TABLE IF NOT EXISTS delivery_events (
    id                    BIGINT AUTO_INCREMENT,
    `timestamp`           DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    message_id            VARCHAR(128) NOT NULL,
    sender                VARCHAR(512) NOT NULL,
    recipient             VARCHAR(512) NOT NULL,
    remote_mx             VARCHAR(256) DEFAULT NULL,
    response_code         SMALLINT DEFAULT NULL,
    response_text         TEXT DEFAULT NULL,
    ip_used               VARCHAR(45) DEFAULT NULL,
    tls_status            TINYINT(1) DEFAULT 0,
    retry_count           SMALLINT DEFAULT 0,
    dkim_status           VARCHAR(32) DEFAULT NULL,
    processing_latency_ms BIGINT DEFAULT NULL,
    status                VARCHAR(32) NOT NULL COMMENT 'delivered, deferred, bounced, failed',
    PRIMARY KEY (id, `timestamp`)
)
ENGINE=InnoDB
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci
PARTITION BY RANGE (YEAR(`timestamp`) * 100 + MONTH(`timestamp`)) (
    PARTITION p202601 VALUES LESS THAN (202602),
    PARTITION p202602 VALUES LESS THAN (202603),
    PARTITION p202603 VALUES LESS THAN (202604),
    PARTITION p202604 VALUES LESS THAN (202605),
    PARTITION p202605 VALUES LESS THAN (202606),
    PARTITION p202606 VALUES LESS THAN (202607),
    PARTITION p202607 VALUES LESS THAN (202608),
    PARTITION p202608 VALUES LESS THAN (202609),
    PARTITION p202609 VALUES LESS THAN (202610),
    PARTITION p202610 VALUES LESS THAN (202611),
    PARTITION p202611 VALUES LESS THAN (202612),
    PARTITION p202612 VALUES LESS THAN (202701),
    PARTITION p_future VALUES LESS THAN MAXVALUE
);

CREATE INDEX idx_events_message_id ON delivery_events (message_id);
CREATE INDEX idx_events_sender ON delivery_events (sender(128));
CREATE INDEX idx_events_recipient ON delivery_events (recipient(128));
CREATE INDEX idx_events_status ON delivery_events (status, `timestamp`);

-- ============================================================================
-- Bounce Records
-- ============================================================================
CREATE TABLE IF NOT EXISTS bounces (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    `timestamp`     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    message_id      VARCHAR(128) NOT NULL,
    sender          VARCHAR(512) NOT NULL,
    recipient       VARCHAR(512) NOT NULL,
    bounce_type     VARCHAR(32) NOT NULL COMMENT 'hard, soft, block, policy, mailbox_full',
    response_code   SMALLINT DEFAULT NULL,
    response_text   TEXT DEFAULT NULL,
    created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_bounces_sender ON bounces (sender(128), `timestamp`);
CREATE INDEX idx_bounces_recipient ON bounces (recipient(128));
CREATE INDEX idx_bounces_type ON bounces (bounce_type, `timestamp`);

-- ============================================================================
-- Suppression List
-- ============================================================================
CREATE TABLE IF NOT EXISTS suppression_list (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    email           VARCHAR(512) NOT NULL,
    reason          VARCHAR(64) NOT NULL COMMENT 'hard_bounce, complaint, manual',
    source_message  VARCHAR(128) DEFAULT NULL,
    created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uk_email (email(255))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Complaints (FBL)
-- ============================================================================
CREATE TABLE IF NOT EXISTS complaints (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    `timestamp`     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    message_id      VARCHAR(128) DEFAULT NULL,
    sender          VARCHAR(512) NOT NULL,
    recipient       VARCHAR(512) NOT NULL,
    feedback_type   VARCHAR(32) DEFAULT NULL COMMENT 'abuse, fraud, not-spam',
    source          VARCHAR(128) DEFAULT NULL COMMENT 'ISP/provider',
    raw_arf         TEXT DEFAULT NULL,
    created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_complaints_sender ON complaints (sender(128), `timestamp`);
CREATE INDEX idx_complaints_recipient ON complaints (recipient(128));

-- ============================================================================
-- Sender Statistics
-- ============================================================================
CREATE TABLE IF NOT EXISTS sender_stats (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    sender          VARCHAR(512) NOT NULL,
    total_sent      BIGINT DEFAULT 0,
    delivered       BIGINT DEFAULT 0,
    hard_bounces    BIGINT DEFAULT 0,
    soft_bounces    BIGINT DEFAULT 0,
    complaints      BIGINT DEFAULT 0,
    bounce_rate     DECIMAL(5,4) DEFAULT 0,
    complaint_rate  DECIMAL(5,4) DEFAULT 0,
    paused          TINYINT(1) DEFAULT 0,
    paused_at       DATETIME(6) DEFAULT NULL,
    updated_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uk_sender (sender(255))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- IP Health Log
-- ============================================================================
CREATE TABLE IF NOT EXISTS ip_health_log (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    ip_address      VARCHAR(45) NOT NULL,
    health_score    DECIMAL(3,2) NOT NULL,
    total_sent      BIGINT DEFAULT 0,
    rate_4xx        DECIMAL(5,4) DEFAULT 0,
    rate_5xx        DECIMAL(5,4) DEFAULT 0,
    timeout_rate    DECIMAL(5,4) DEFAULT 0,
    tls_fail_rate   DECIMAL(5,4) DEFAULT 0,
    disabled        TINYINT(1) DEFAULT 0,
    recorded_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_ip_health_ip ON ip_health_log (ip_address, recorded_at);

-- ============================================================================
-- Domain Delivery Statistics
-- ============================================================================
CREATE TABLE IF NOT EXISTS domain_stats (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    domain          VARCHAR(256) NOT NULL,
    `date`          DATE NOT NULL,
    total_sent      BIGINT DEFAULT 0,
    delivered       BIGINT DEFAULT 0,
    bounced         BIGINT DEFAULT 0,
    deferred        BIGINT DEFAULT 0,
    complaints      BIGINT DEFAULT 0,
    avg_latency_ms  BIGINT DEFAULT 0,
    UNIQUE KEY uk_domain_date (domain(128), `date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- API Users (for admin dashboard)
-- ============================================================================
CREATE TABLE IF NOT EXISTS api_users (
    id              CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    username        VARCHAR(128) NOT NULL,
    password_hash   VARCHAR(256) NOT NULL,
    role            VARCHAR(32) NOT NULL DEFAULT 'viewer' COMMENT 'admin, operator, viewer',
    api_key         VARCHAR(128) DEFAULT NULL,
    created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    last_login      DATETIME(6) DEFAULT NULL,
    UNIQUE KEY uk_username (username),
    UNIQUE KEY uk_api_key (api_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Audit Log
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    `timestamp`     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    user_id         CHAR(36) DEFAULT NULL,
    action          VARCHAR(128) NOT NULL,
    resource        VARCHAR(256) DEFAULT NULL,
    details         JSON DEFAULT NULL,
    ip_address      VARCHAR(45) DEFAULT NULL,
    CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES api_users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_audit_timestamp ON audit_log (`timestamp`);
CREATE INDEX idx_audit_user ON audit_log (user_id);

-- ============================================================================
-- Retention Policy
-- ============================================================================
-- For automated partition management, use a monthly MySQL EVENT that drops
-- the oldest partition and adds a new one for the upcoming month.
--
-- Recommended retention: 90 days for events, 365 days for bounces/complaints
