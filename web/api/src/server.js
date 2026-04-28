/**
 * SRMTA Admin API Server
 * Fastify-based REST API with JWT authentication, RBAC, rate limiting,
 * WebSocket live updates, and full CRUD for mail platform management.
 */

const fastify = require('fastify')({ logger: true });
const { Pool } = require('pg');

// ── Configuration ─────────────────────────────────────────────────────────
// Fail fast if critical secrets are not configured
if (!process.env.JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is required');
  process.exit(1);
}
if (!process.env.DB_PASSWORD) {
  console.error('FATAL: DB_PASSWORD environment variable is required');
  process.exit(1);
}
if (!process.env.WEBHOOK_SECRET) {
  console.error('FATAL: WEBHOOK_SECRET environment variable is required (separate from JWT_SECRET)');
  process.exit(1);
}

const config = {
  port: Number.parseInt(process.env.API_PORT || '3000'),
  host: process.env.API_HOST || '0.0.0.0',
  jwtSecret: process.env.JWT_SECRET,
  webhookSecret: process.env.WEBHOOK_SECRET,
  allowedOrigins: (process.env.ALLOWED_ORIGINS || '').split(',').filter(Boolean),
  db: {
    host: process.env.DB_HOST || 'localhost',
    port: Number.parseInt(process.env.DB_PORT || '5432'),
    user: process.env.DB_USER || 'srmta',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'srmta',
  },
  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379',
  },
};

// ── PostgreSQL Pool ───────────────────────────────────────────────────────
const pool = new Pool({
  host: config.db.host,
  port: config.db.port,
  user: config.db.user,
  password: config.db.password,
  database: config.db.database,
  max: 20,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
  ssl: { rejectUnauthorized: false },
});

pool.on('error', (err) => {
  fastify.log.error({ err }, 'pg_pool_error');
});

// ── Utils ─────────────────────────────────────────────────────────────────
/**
 * Escape a single CSV field per RFC 4180.
 * Wraps in quotes if it contains comma, quote, CR, or LF; doubles internal quotes.
 */
function csvEscape(value) {
  if (value === null || value === undefined) return '';
  const s = String(value);
  if (/[",\r\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

/**
 * Mask an email address for privacy in logs.
 * user@domain.com -> u***r@domain.com
 */
function maskEmail(email) {
  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return email;
  }
  const [user, domain] = email.split('@');
  if (user.length <= 1) return `*@${domain}`;
  if (user.length === 2) return `${user[0]}*@${domain}`;
  return `${user[0]}***${user.at(-1)}@${domain}`;
}

/**
 * Redact PII from a webhook data object.
 */
function redactWebhookData(data) {
  if (!data || typeof data !== 'object') return data;
  const redacted = { ...data };
  if (redacted.sender) redacted.sender = maskEmail(redacted.sender);
  if (redacted.recipient) redacted.recipient = maskEmail(redacted.recipient);
  return redacted;
}

// ── Register Plugins ──────────────────────────────────────────────────────
async function registerPlugins() {
  // CORS — restrict to explicit origins
  await fastify.register(require('@fastify/cors'), {
    origin: config.allowedOrigins.length > 0 ? config.allowedOrigins : false,
    credentials: true,
  });

  // JWT Authentication
  await fastify.register(require('@fastify/jwt'), {
    secret: config.jwtSecret,
    sign: { expiresIn: '30m' },
  });

  // Rate Limiting
  await fastify.register(require('@fastify/rate-limit'), {
    max: 100,
    timeWindow: '1 minute',
  });

  // WebSocket
  await fastify.register(require('@fastify/websocket'));
}

// ── Authentication Decorator ──────────────────────────────────────────────
function authDecorator() {
  fastify.decorate('authenticate', async function (request, reply) {
    try {
      await request.jwtVerify();
    } catch (err) {
      request.log.warn({ err }, 'jwt_verify_failed');
      reply.code(401).send({ error: 'Unauthorized', message: 'Invalid or expired token' });
    }
  });

  fastify.decorate('requireRole', function (roles) {
    return async function (request, reply) {
      await request.jwtVerify();
      if (!roles.includes(request.user.role)) {
        reply.code(403).send({ error: 'Forbidden', message: 'Insufficient permissions' });
      }
    };
  });
}

// ── Health Check ──────────────────────────────────────────────────────────
function healthRoutes() {
  fastify.get('/health', async () => ({
    status: 'healthy',
    service: 'srmta-api',
    timestamp: new Date().toISOString(),
  }));
}

// ── Auth Routes ───────────────────────────────────────────────────────────
function authRoutes() {
  // POST /api/auth/login — stricter rate limit for login
  fastify.post('/api/auth/login', {
    config: { rateLimit: { max: 10, timeWindow: '1 minute' } },
  }, async (request, reply) => {
    const { username, password } = request.body || {};
    if (!username || !password) {
      return reply.code(400).send({ error: 'Username and password required' });
    }

    // Validate against database
    const bcrypt = require('bcryptjs');
    try {
      const result = await pool.query(
        'SELECT id, username, password_hash, role FROM api_users WHERE username = $1',
        [username]
      );
      const user = result.rows[0];
      if (!user) {
        return reply.code(401).send({ error: 'Invalid credentials' });
      }
      const valid = await bcrypt.compare(password, user.password_hash);
      if (!valid) {
        return reply.code(401).send({ error: 'Invalid credentials' });
      }
      // Best-effort last_login update; do not block auth on failure.
      pool.query('UPDATE api_users SET last_login = NOW() WHERE id = $1', [user.id])
        .catch((err) => fastify.log.warn({ err }, 'last_login_update_failed'));
      const token = fastify.jwt.sign({
        id: user.id,
        username: user.username,
        role: user.role,
      });
      return { token, user: { id: user.id, username: user.username, role: user.role } };
    } catch (err) {
      fastify.log.error({ err }, 'login_error');
      return reply.code(500).send({ error: 'Internal server error' });
    }
  });

  // GET /api/auth/me
  fastify.get('/api/auth/me', { preHandler: [fastify.authenticate] }, async (request) => {
    return { user: request.user };
  });
}

// ── Send Routes ───────────────────────────────────────────────────────────
function sendRoutes() {
  // POST /api/send — Send a single email
  // RBAC Fix: Restrict to admin/operator
  fastify.post('/api/send', {
    preHandler: [fastify.requireRole(['admin', 'operator'])],
  }, async (request, reply) => {
    const { from, to, subject } = request.body || {};

    if (!from || !to || !subject) {
      return reply.code(400).send({ error: 'from, to, and subject are required' });
    }

    const crypto = require('node:crypto');
    const messageId = crypto.randomUUID();

    // TODO: Enqueue to SMTP engine via Redis
    return {
      message_id: messageId,
      status: 'queued',
      queued_at: new Date().toISOString(),
    };
  });

  // POST /api/bulk — Send bulk emails
  // RBAC Fix: Restrict to admin/operator
  fastify.post('/api/bulk', {
    preHandler: [fastify.requireRole(['admin', 'operator'])],
  }, async (request, reply) => {
    const { messages } = request.body || {};

    if (!Array.isArray(messages) || messages.length === 0) {
      return reply.code(400).send({ error: 'messages array is required' });
    }

    const MAX_BULK_SIZE = 1000;
    if (messages.length > MAX_BULK_SIZE) {
      return reply.code(400).send({ error: `Maximum ${MAX_BULK_SIZE} messages per batch` });
    }

    const crypto = require('node:crypto');
    const results = messages.map((msg, idx) => ({
      index: idx,
      message_id: crypto.randomUUID(),
      status: 'queued',
    }));

    return { total: messages.length, results };
  });

  // POST /api/schedule — Schedule an email
  // RBAC Fix: Restrict to admin/operator
  fastify.post('/api/schedule', {
    preHandler: [fastify.requireRole(['admin', 'operator'])],
  }, async (request, reply) => {
    const { from, to, subject, send_at } = request.body || {};

    if (!from || !to || !subject || !send_at) {
      return reply.code(400).send({ error: 'from, to, subject, and send_at are required' });
    }

    const crypto = require('node:crypto');
    const messageId = `sched-${crypto.randomUUID()}`;

    return {
      message_id: messageId,
      status: 'scheduled',
      scheduled_at: send_at,
    };
  });
}

// ── Status Routes ─────────────────────────────────────────────────────────
function statusRoutes() {
  // GET /api/status/:id
  // Note: delivery_events has no user_id column; per-row ownership is not
  // representable in the current schema. Restricting to admin/operator avoids
  // exposing arbitrary message metadata to viewer-level accounts.
  fastify.get('/api/status/:id', {
    preHandler: [fastify.requireRole(['admin', 'operator'])],
  }, async (request, reply) => {
    const { id } = request.params;

    try {
      const result = await pool.query(
        `SELECT message_id, status, sender, recipient, remote_mx,
                response_code, response_text, ip_used, tls_status,
                retry_count, dkim_status, processing_latency_ms, timestamp
           FROM delivery_events
          WHERE message_id = $1
          ORDER BY timestamp DESC
          LIMIT 1`,
        [id]
      );
      if (result.rows.length === 0) {
        return reply.code(404).send({ error: 'Not Found', message: 'Message not found' });
      }
      const row = result.rows[0];
      return {
        message_id: row.message_id,
        status: row.status,
        sender: row.sender,
        recipient: row.recipient,
        remote_mx: row.remote_mx,
        response_code: row.response_code,
        response_text: row.response_text,
        ip_used: row.ip_used,
        tls_status: row.tls_status,
        retry_count: row.retry_count,
        dkim_status: row.dkim_status,
        processing_latency_ms: row.processing_latency_ms,
        timestamp: row.timestamp,
      };
    } catch (err) {
      fastify.log.error({ err }, 'status_query_error');
      return reply.code(500).send({ error: 'Internal server error' });
    }
  });
}

// ── Metrics Routes ────────────────────────────────────────────────────────
function metricsRoutes() {
  // GET /api/metrics
  // RBAC Fix: Restrict to admin/operator
  fastify.get('/api/metrics', {
    preHandler: [fastify.requireRole(['admin', 'operator'])],
  }, async (request, reply) => {
    // Aggregates the last 24h from delivery_events. Bounded window avoids
    // scanning every monthly partition.
    try {
      const result = await pool.query(
        `SELECT
            COUNT(*)::bigint                                                    AS total_sent,
            COUNT(*) FILTER (WHERE status = 'delivered')::bigint                AS delivered,
            COUNT(*) FILTER (WHERE status = 'bounced')::bigint                  AS bounced,
            COUNT(*) FILTER (WHERE status = 'deferred')::bigint                 AS deferred,
            COUNT(*) FILTER (WHERE status = 'failed')::bigint                   AS failed,
            COALESCE(AVG(processing_latency_ms) FILTER (WHERE status = 'delivered'), 0)::bigint AS avg_latency_ms
           FROM delivery_events
          WHERE timestamp > NOW() - INTERVAL '24 hours'`
      );
      const r = result.rows[0] || {};
      const total = Number(r.total_sent || 0);
      const delivered = Number(r.delivered || 0);
      const success_rate = total > 0 ? delivered / total : 0;
      return {
        timestamp: new Date().toISOString(),
        window: 'last_24h',
        delivery: {
          total_sent: total,
          delivered,
          bounced: Number(r.bounced || 0),
          deferred: Number(r.deferred || 0),
          failed: Number(r.failed || 0),
          success_rate,
        },
        queue: {
          incoming: 0,
          active: 0,
          deferred: 0,
          retry: 0,
          dead_letter: 0,
          failed: 0,
        },
        smtp: {
          active_connections: 0,
          messages_per_second: 0,
          avg_latency_ms: Number(r.avg_latency_ms || 0),
        },
        ip_pool: [],
      };
    } catch (err) {
      fastify.log.error({ err }, 'metrics_query_error');
      return reply.code(500).send({ error: 'Internal server error' });
    }
  });
}

// ── Webhook Routes ────────────────────────────────────────────────────────
function webhookRoutes() {
  // POST /api/webhook — Receive delivery status webhooks
  fastify.post('/api/webhook', async (request, reply) => {
    const signature = request.headers['x-srmta-signature'];

    // Validate HMAC-SHA256 signature
    if (!signature) {
      return reply.code(401).send({ error: 'Missing webhook signature' });
    }

    const crypto = require('node:crypto');
    const bodyStr = JSON.stringify(request.body);
    const expectedSig = crypto
      .createHmac('sha256', config.webhookSecret)
      .update(bodyStr)
      .digest('hex');

    const expected = Buffer.from(`sha256=${expectedSig}`, 'utf8');
    const received = Buffer.from(signature, 'utf8');
    if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) {
      return reply.code(401).send({ error: 'Invalid webhook signature' });
    }

    // Process webhook
    const { event_type, data } = request.body || {};
    // Privacy Fix: Redact PII in webhook logs
    fastify.log.info({ event_type, data: redactWebhookData(data) }, 'Webhook received');

    return { status: 'received' };
  });
}

// ── Log Export Routes ─────────────────────────────────────────────────────
/**
 * Build a parameterized WHERE clause from log filters.
 * Returns { where: 'WHERE ...' | '', params: [...] }.
 */
function buildLogFilters(query) {
  const params = [];
  const clauses = [];
  if (query.status) {
    params.push(query.status);
    clauses.push(`status = $${params.length}`);
  }
  if (query.sender) {
    params.push(query.sender);
    clauses.push(`sender = $${params.length}`);
  }
  if (query.recipient) {
    params.push(query.recipient);
    clauses.push(`recipient = $${params.length}`);
  }
  return {
    where: clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '',
    params,
  };
}

function logRoutes() {
  const CSV_COLUMNS = [
    'timestamp', 'message_id', 'sender', 'recipient', 'remote_mx',
    'response_code', 'response_text', 'ip_used', 'tls_status',
    'retry_count', 'dkim_status', 'processing_latency_ms', 'status',
  ];

  // GET /api/logs/export
  // RBAC Fix: Restrict to admin/operator
  fastify.get('/api/logs/export', {
    preHandler: [fastify.requireRole(['admin', 'operator'])],
  }, async (request, reply) => {
    const limit = Math.min(Number.parseInt(request.query.limit) || 10000, 50000);
    const { where, params } = buildLogFilters(request.query);
    params.push(limit);

    reply.header('Content-Type', 'text/csv');
    reply.header('Content-Disposition', `attachment; filename="srmta-logs-${Date.now()}.csv"`);

    let result;
    try {
      result = await pool.query(
        `SELECT ${CSV_COLUMNS.join(', ')}
           FROM delivery_events
           ${where}
           ORDER BY timestamp DESC
           LIMIT $${params.length}`,
        params
      );
    } catch (err) {
      fastify.log.error({ err }, 'logs_export_query_error');
      return reply.code(500).send({ error: 'Internal server error' });
    }

    // "Streaming-ish": hijack and write rows to the raw socket so we don't
    // build a giant string in memory.
    reply.hijack();
    const raw = reply.raw;
    raw.setHeader('Content-Type', 'text/csv');
    raw.setHeader('Content-Disposition', `attachment; filename="srmta-logs-${Date.now()}.csv"`);
    raw.write(`${CSV_COLUMNS.join(',')}\n`);
    for (const row of result.rows) {
      const line = CSV_COLUMNS.map((c) => csvEscape(row[c])).join(',');
      raw.write(`${line}\n`);
    }
    raw.end();
  });

  // GET /api/logs — Paginated log viewer
  // RBAC Fix: Restrict to admin/operator
  fastify.get('/api/logs', {
    preHandler: [fastify.requireRole(['admin', 'operator'])],
  }, async (request, reply) => {
    const page = Math.max(1, Number.parseInt(request.query.page) || 1);
    const per_page = Math.min(Math.max(1, Number.parseInt(request.query.per_page) || 50), 200);
    const offset = (page - 1) * per_page;

    const { where, params } = buildLogFilters(request.query);

    try {
      const dataParams = [...params, per_page, offset];
      const dataSql = `
        SELECT timestamp, message_id, sender, recipient, remote_mx,
               response_code, response_text, ip_used, tls_status,
               retry_count, dkim_status, processing_latency_ms, status
          FROM delivery_events
          ${where}
          ORDER BY timestamp DESC
          LIMIT $${dataParams.length - 1} OFFSET $${dataParams.length}`;
      const countSql = `SELECT COUNT(*)::bigint AS total FROM delivery_events ${where}`;

      const [dataResult, countResult] = await Promise.all([
        pool.query(dataSql, dataParams),
        pool.query(countSql, params),
      ]);

      const total = Number(countResult.rows[0]?.total || 0);
      return {
        data: dataResult.rows,
        pagination: {
          page,
          per_page,
          total,
          total_pages: Math.ceil(total / per_page),
        },
      };
    } catch (err) {
      fastify.log.error({ err }, 'logs_query_error');
      return reply.code(500).send({ error: 'Internal server error' });
    }
  });
}

// ── Queue Management Routes ───────────────────────────────────────────────
function queueRoutes() {
  // GET /api/queue/stats
  // Stub: queue depth lives in Redis / on-disk spool dirs (see internal/queue),
  // not in PostgreSQL. Wiring this up requires Redis integration which is out
  // of scope for this change.
  fastify.get('/api/queue/stats', { preHandler: [fastify.authenticate] }, async () => {
    return {
      spools: {
        incoming: { depth: 0, oldest_message: null },
        active: { depth: 0, oldest_message: null },
        deferred: { depth: 0, oldest_message: null },
        retry: { depth: 0, oldest_message: null },
        dead_letter: { depth: 0, oldest_message: null },
        failed: { depth: 0, oldest_message: null },
      },
      total_depth: 0,
      processing_rate: 0,
    };
  });

  // POST /api/queue/flush — Flush a specific spool
  fastify.post('/api/queue/flush', {
    preHandler: [fastify.requireRole(['admin'])],
  }, async (request) => {
    const { spool } = request.body || {};
    return { status: 'flushed', spool };
  });
}

// ── Domain & IP Routes ────────────────────────────────────────────────────
function domainRoutes() {
  // GET /api/domains/stats
  fastify.get('/api/domains/stats', { preHandler: [fastify.authenticate] }, async () => {
    return { domains: [] };
  });

  // GET /api/ips — IP pool health
  // No `ip_pool` table in schema; pulls latest health snapshot per IP from
  // `ip_health_log`.
  fastify.get('/api/ips', { preHandler: [fastify.authenticate] }, async (request, reply) => {
    try {
      const result = await pool.query(
        `SELECT DISTINCT ON (ip_address)
                ip_address, health_score, total_sent,
                rate_4xx, rate_5xx, timeout_rate, tls_fail_rate,
                disabled, recorded_at
           FROM ip_health_log
          ORDER BY ip_address, recorded_at DESC`
      );
      return { ips: result.rows };
    } catch (err) {
      fastify.log.error({ err }, 'ips_query_error');
      return reply.code(500).send({ error: 'Internal server error' });
    }
  });

  // POST /api/ips/:address/disable
  fastify.post('/api/ips/:address/disable', {
    preHandler: [fastify.requireRole(['admin', 'operator'])],
  }, async (request) => {
    return { status: 'disabled', address: request.params.address };
  });

  // POST /api/ips/:address/enable
  fastify.post('/api/ips/:address/enable', {
    preHandler: [fastify.requireRole(['admin', 'operator'])],
  }, async (request) => {
    return { status: 'enabled', address: request.params.address };
  });
}

// ── WebSocket Live Updates ────────────────────────────────────────────────
function websocketRoutes() {
  fastify.get('/ws', { websocket: true, preHandler: [fastify.authenticate] }, (socket, request) => {
    socket.on('message', (message) => {
      // Handle subscription requests
      try {
        const data = JSON.parse(message.toString());
        if (data.type === 'subscribe') {
          socket.send(JSON.stringify({
            type: 'subscribed',
            channel: data.channel,
          }));
        }
      } catch (e) {
        fastify.log.warn({ err: e }, 'ws_invalid_json');
        socket.send(JSON.stringify({ type: 'error', message: 'Invalid JSON' }));
      }
    });

    // Send periodic updates
    const interval = setInterval(() => {
      socket.send(JSON.stringify({
        type: 'metrics_update',
        timestamp: new Date().toISOString(),
        data: {
          queue_depth: 0,
          delivery_rate: 0,
          active_connections: 0,
        },
      }));
    }, 5000);

    socket.on('close', () => {
      clearInterval(interval);
    });
  });
}

// ── Start Server ──────────────────────────────────────────────────────────
async function start() {
  try {
    await registerPlugins();
    authDecorator();
    healthRoutes();
    authRoutes();
    sendRoutes();
    statusRoutes();
    metricsRoutes();
    webhookRoutes();
    logRoutes();
    queueRoutes();
    domainRoutes();
    websocketRoutes();

    await fastify.listen({ port: config.port, host: config.host });
    fastify.log.info(`SRMTA API listening on ${config.host}:${config.port}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

// ── Graceful Shutdown ─────────────────────────────────────────────────────
let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  fastify.log.info({ signal }, 'shutting_down');
  try {
    await fastify.close();
  } catch (err) {
    fastify.log.error({ err }, 'fastify_close_error');
  }
  try {
    await pool.end();
  } catch (err) {
    fastify.log.error({ err }, 'pg_pool_close_error');
  }
  process.exit(0);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

start();
