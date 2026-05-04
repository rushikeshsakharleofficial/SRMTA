/**
 * SRMTA Admin API Server
 * Fastify-based REST API with JWT authentication, RBAC, rate limiting,
 * WebSocket live updates, and full CRUD for mail platform management.
 */

const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const crypto = require('node:crypto');
const fastify = require('fastify')({ logger: true });
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`FATAL: ${name} environment variable is required`);
    process.exit(1);
  }
  return value;
}

const jwtSecret = requireEnv('JWT_SECRET');
const dbPassword = requireEnv('DB_PASSWORD');
const webhookSecret = requireEnv('WEBHOOK_SECRET');

function buildDbSslConfig() {
  const mode = process.env.DB_SSL_MODE || 'require';
  if (mode === 'disable') return false;
  if (mode === 'insecure') {
    if (process.env.NODE_ENV === 'production') {
      console.error('FATAL: DB_SSL_MODE=insecure is not allowed in production');
      process.exit(1);
    }
    return { rejectUnauthorized: false };
  }
  if (mode === 'verify-full' || mode === 'require') {
    const caFile = process.env.DB_CA_FILE;
    if (caFile) {
      return { rejectUnauthorized: true, ca: fs.readFileSync(caFile, 'utf8') };
    }
    return { rejectUnauthorized: true };
  }
  console.error('FATAL: DB_SSL_MODE must be one of disable, require, verify-full, insecure');
  process.exit(1);
}

const config = {
  port: Number.parseInt(process.env.API_PORT || '3000', 10),
  host: process.env.API_HOST || '0.0.0.0',
  jwtSecret,
  jwtIssuer: process.env.JWT_ISSUER || 'srmta-api',
  jwtAudience: process.env.JWT_AUDIENCE || 'srmta-admin',
  webhookSecret,
  webhookToleranceSeconds: Number.parseInt(process.env.WEBHOOK_TOLERANCE_SECONDS || '300', 10),
  allowedOrigins: (process.env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean),
  db: {
    host: process.env.DB_HOST || 'localhost',
    port: Number.parseInt(process.env.DB_PORT || '5432', 10),
    user: process.env.DB_USER || 'srmta',
    password: dbPassword,
    database: process.env.DB_NAME || 'srmta',
    ssl: buildDbSslConfig(),
  },
  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379',
  },
  spoolDir: process.env.SPOOL_DIR || '/var/spool/srmta',
  smtpHost: process.env.SMTP_HOST || '127.0.0.1',
  smtpPort: Number.parseInt(process.env.SMTP_PORT || '25', 10),
};

const pool = new Pool({
  host: config.db.host,
  port: config.db.port,
  user: config.db.user,
  password: config.db.password,
  database: config.db.database,
  max: 20,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
  ssl: config.db.ssl,
});

pool.on('error', (err) => {
  fastify.log.error({ err }, 'pg_pool_error');
});

const emailString = { type: 'string', minLength: 3, maxLength: 320 };
const messageSchema = {
  type: 'object',
  required: ['from', 'to', 'subject'],
  additionalProperties: false,
  properties: {
    from: emailString,
    to: emailString,
    subject: { type: 'string', minLength: 1, maxLength: 255 },
    body: { type: 'string', maxLength: 1_048_576 },
  },
};

function csvEscape(value) {
  if (value === null || value === undefined) return '';
  const s = String(value);
  if (/[",\r\n]/.test(s)) {
    return `"${s.replaceAll('"', '""')}"`;
  }
  return s;
}

function maskEmail(email) {
  if (!email || typeof email !== 'string' || !email.includes('@')) return email;
  const [user, domain] = email.split('@');
  if (user.length <= 1) return `*@${domain}`;
  if (user.length === 2) return `${user[0]}*@${domain}`;
  return `${user[0]}***${user.at(-1)}@${domain}`;
}

function redactWebhookData(data) {
  if (!data || typeof data !== 'object') return data;
  const redacted = { ...data };
  if (redacted.sender) redacted.sender = maskEmail(redacted.sender);
  if (redacted.recipient) redacted.recipient = maskEmail(redacted.recipient);
  return redacted;
}

async function countSpool(spoolName) {
  const dirName = spoolName === 'dead_letter' ? 'dead-letter' : spoolName;
  const spoolPath = path.join(config.spoolDir, dirName);
  let depth = 0;
  let oldestMs = null;
  try {
    const shardDirs = await fs.promises.readdir(spoolPath);
    for (const sd of shardDirs) {
      const sdPath = path.join(spoolPath, sd);
      const files = await fs.promises.readdir(sdPath).catch(() => []);
      for (const f of files) {
        if (!f.endsWith('.meta')) continue;
        depth++;
        if (oldestMs === null) {
          const stat = await fs.promises.stat(path.join(sdPath, f)).catch(() => null);
          if (stat) oldestMs = stat.mtimeMs;
        }
      }
    }
  } catch {}
  return { depth, oldest_message: oldestMs ? new Date(oldestMs).toISOString() : null };
}

function injectViaSMTP(from, to, rawMessage) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: config.smtpHost, port: config.smtpPort });
    let step = 0;
    socket.setTimeout(15000);
    socket.on('timeout', () => { socket.destroy(); reject(new Error('SMTP timeout')); });
    socket.on('error', reject);
    const send = (s) => socket.write(s + '\r\n');
    socket.on('data', (chunk) => {
      const resp = chunk.toString();
      const code = resp.slice(0, 3);
      if (code === '220' && step === 0) { step = 1; send('EHLO api'); }
      else if (code === '250' && step === 1) { step = 2; send('MAIL FROM:<' + from + '>'); }
      else if (code === '250' && step === 2) { step = 3; send('RCPT TO:<' + to + '>'); }
      else if (code === '250' && step === 3) { step = 4; send('DATA'); }
      else if (code === '354') { socket.write(rawMessage + '\r\n.\r\n'); send('QUIT'); step = 5; }
      else if ((code === '250' || code === '221') && step === 5) { socket.end(); resolve(); }
      else if (code[0] === '4' || code[0] === '5') { socket.destroy(); reject(new Error('SMTP ' + resp.trim())); }
    });
  });
}

function verifyWebhookSignature(request) {
  const signature = request.headers['x-srmta-signature'];
  const timestampHeader = request.headers['x-srmta-timestamp'];
  if (!signature) return { ok: false, error: 'Missing webhook signature' };
  if (!timestampHeader) return { ok: false, error: 'Missing webhook timestamp' };

  const timestamp = Number.parseInt(timestampHeader, 10);
  if (!Number.isFinite(timestamp)) return { ok: false, error: 'Invalid webhook timestamp' };
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > config.webhookToleranceSeconds) {
    return { ok: false, error: 'Webhook timestamp outside tolerance' };
  }

  const payload = request.rawBody || '';
  const expectedSig = crypto
    .createHmac('sha256', config.webhookSecret)
    .update(`${timestamp}.${payload}`)
    .digest('hex');
  const expected = Buffer.from(`sha256=${expectedSig}`, 'utf8');
  const received = Buffer.from(String(signature), 'utf8');
  if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) {
    return { ok: false, error: 'Invalid webhook signature' };
  }
  return { ok: true };
}

async function registerPlugins() {
  fastify.addContentTypeParser('application/json', { parseAs: 'string' }, (request, body, done) => {
    request.rawBody = body;
    try {
      done(null, body ? JSON.parse(body) : {});
    } catch (err) {
      err.statusCode = 400;
      done(err, undefined);
    }
  });

  await fastify.register(require('@fastify/cors'), {
    origin: config.allowedOrigins.length > 0 ? config.allowedOrigins : false,
    credentials: true,
  });

  await fastify.register(require('@fastify/jwt'), {
    secret: config.jwtSecret,
    sign: {
      expiresIn: '30m',
      issuer: config.jwtIssuer,
      audience: config.jwtAudience,
    },
    verify: {
      issuer: config.jwtIssuer,
      audience: config.jwtAudience,
    },
  });

  await fastify.register(require('@fastify/rate-limit'), {
    max: 100,
    timeWindow: '1 minute',
  });

  await fastify.register(require('@fastify/websocket'));
}

function authDecorator() {
  fastify.decorate('authenticate', async function (request, reply) {
    try {
      await request.jwtVerify();
    } catch (err) {
      request.log.warn({ err }, 'jwt_verify_failed');
      return reply.code(401).send({ error: 'Unauthorized', message: 'Invalid or expired token' });
    }
  });

  fastify.decorate('requireRole', function (roles) {
    return async function (request, reply) {
      try {
        await request.jwtVerify();
      } catch (err) {
        request.log.warn({ err }, 'jwt_verify_failed');
        return reply.code(401).send({ error: 'Unauthorized', message: 'Invalid or expired token' });
      }
      if (!roles.includes(request.user.role)) {
        return reply.code(403).send({ error: 'Forbidden', message: 'Insufficient permissions' });
      }
    };
  });
}

function healthRoutes() {
  fastify.get('/health', async () => ({
    status: 'healthy',
    service: 'srmta-api',
    timestamp: new Date().toISOString(),
  }));
}

function authRoutes() {
  fastify.post('/api/auth/login', {
    config: { rateLimit: { max: 10, timeWindow: '1 minute' } },
    schema: {
      body: {
        type: 'object',
        required: ['username', 'password'],
        additionalProperties: false,
        properties: {
          username: { type: 'string', minLength: 1, maxLength: 128 },
          password: { type: 'string', minLength: 1, maxLength: 1024 },
        },
      },
    },
  }, async (request, reply) => {
    const { username, password } = request.body;
    try {
      const result = await pool.query(
        'SELECT id, username, password_hash, role FROM api_users WHERE username = $1',
        [username]
      );
      const user = result.rows[0];
      if (!user || !(await bcrypt.compare(password, user.password_hash))) {
        return reply.code(401).send({ error: 'Invalid credentials' });
      }
      pool.query('UPDATE api_users SET last_login = NOW() WHERE id = $1', [user.id])
        .catch((err) => fastify.log.warn({ err }, 'last_login_update_failed'));
      const token = fastify.jwt.sign({ id: user.id, username: user.username, role: user.role });
      return { token, user: { id: user.id, username: user.username, role: user.role } };
    } catch (err) {
      fastify.log.error({ err }, 'login_error');
      return reply.code(500).send({ error: 'Internal server error' });
    }
  });

  fastify.get('/api/auth/me', { preHandler: [fastify.authenticate] }, async (request) => ({ user: request.user }));
}

function sendRoutes() {
  fastify.post('/api/send', {
    preHandler: [fastify.requireRole(['admin', 'operator'])],
    schema: { body: messageSchema },
  }, async (request, reply) => {
    const { from, to, subject, text, html } = request.body;
    const body = [
      'From: ' + from,
      'To: ' + to,
      'Subject: ' + subject,
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=utf-8',
      '',
      text || html || '',
    ].join('\r\n');
    try {
      await injectViaSMTP(from, to, body);
      return { queued: true };
    } catch (err) {
      fastify.log.error({ err }, 'smtp_inject_error');
      return reply.code(502).send({ error: 'Delivery failed', detail: err.message });
    }
  });

}

function statusRoutes() {
  fastify.get('/api/status/:id', {
    preHandler: [fastify.requireRole(['admin', 'operator'])],
    schema: { params: { type: 'object', required: ['id'], properties: { id: { type: 'string', minLength: 1, maxLength: 128 } } } },
  }, async (request, reply) => {
    try {
      const result = await pool.query(
        `SELECT message_id, status, sender, recipient, remote_mx,
                response_code, response_text, ip_used, tls_status,
                retry_count, dkim_status, processing_latency_ms, timestamp
           FROM delivery_events
          WHERE message_id = $1
          ORDER BY timestamp DESC
          LIMIT 1`,
        [request.params.id]
      );
      if (result.rows.length === 0) {
        return reply.code(404).send({ error: 'Not Found', message: 'Message not found' });
      }
      return result.rows[0];
    } catch (err) {
      fastify.log.error({ err }, 'status_query_error');
      return reply.code(500).send({ error: 'Internal server error' });
    }
  });
}

function metricsRoutes() {
  fastify.get('/api/metrics', { preHandler: [fastify.requireRole(['admin', 'operator'])] }, async (request, reply) => {
    try {
      const result = await pool.query(
        `SELECT
            COUNT(*)::bigint AS total_sent,
            COUNT(*) FILTER (WHERE status = 'delivered')::bigint AS delivered,
            COUNT(*) FILTER (WHERE status = 'bounced')::bigint AS bounced,
            COUNT(*) FILTER (WHERE status = 'deferred')::bigint AS deferred,
            COUNT(*) FILTER (WHERE status = 'failed')::bigint AS failed,
            COALESCE(AVG(processing_latency_ms) FILTER (WHERE status = 'delivered'), 0)::bigint AS avg_latency_ms
           FROM delivery_events
          WHERE timestamp > NOW() - INTERVAL '24 hours'`
      );
      const r = result.rows[0] || {};
      const total = Number(r.total_sent || 0);
      const delivered = Number(r.delivered || 0);
      return {
        timestamp: new Date().toISOString(),
        window: 'last_24h',
        delivery: {
          total_sent: total,
          delivered,
          bounced: Number(r.bounced || 0),
          deferred: Number(r.deferred || 0),
          failed: Number(r.failed || 0),
          success_rate: total > 0 ? delivered / total : 0,
        },
        queue: { incoming: 0, active: 0, deferred: 0, retry: 0, dead_letter: 0, failed: 0 },
        smtp: { active_connections: 0, messages_per_second: 0, avg_latency_ms: Number(r.avg_latency_ms || 0) },
        ip_pool: [],
      };
    } catch (err) {
      fastify.log.error({ err }, 'metrics_query_error');
      return reply.code(500).send({ error: 'Internal server error' });
    }
  });
}

function webhookRoutes() {
  fastify.post('/api/webhook', {
    schema: {
      body: {
        type: 'object',
        required: ['event_type', 'data'],
        additionalProperties: true,
        properties: {
          event_type: { type: 'string', minLength: 1, maxLength: 128 },
          data: { type: 'object' },
        },
      },
    },
  }, async (request, reply) => {
    const verification = verifyWebhookSignature(request);
    if (!verification.ok) return reply.code(401).send({ error: verification.error });
    const { event_type, data } = request.body;
    fastify.log.info({ event_type, data: redactWebhookData(data) }, 'webhook_received');
    return { status: 'received' };
  });
}

function buildLogFilters(query) {
  const params = [];
  const clauses = [];
  if (query.status) { params.push(query.status); clauses.push(`status = $${params.length}`); }
  if (query.sender) { params.push(query.sender); clauses.push(`sender = $${params.length}`); }
  if (query.recipient) { params.push(query.recipient); clauses.push(`recipient = $${params.length}`); }
  return { where: clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '', params };
}

function logRoutes() {
  const CSV_COLUMNS = ['timestamp', 'message_id', 'sender', 'recipient', 'remote_mx', 'response_code', 'response_text', 'ip_used', 'tls_status', 'retry_count', 'dkim_status', 'processing_latency_ms', 'status'];
  const querySchema = {
    type: 'object',
    additionalProperties: false,
    properties: {
      status: { type: 'string', maxLength: 32 },
      sender: emailString,
      recipient: emailString,
      limit: { type: 'integer', minimum: 1, maximum: 50000 },
      page: { type: 'integer', minimum: 1 },
      per_page: { type: 'integer', minimum: 1, maximum: 200 },
    },
  };

  fastify.get('/api/logs/export', { preHandler: [fastify.requireRole(['admin', 'operator'])], schema: { querystring: querySchema } }, async (request, reply) => {
    const limit = Math.min(Number.parseInt(request.query.limit, 10) || 10000, 50000);
    const { where, params } = buildLogFilters(request.query);
    params.push(limit);
    try {
      const result = await pool.query(`SELECT ${CSV_COLUMNS.join(', ')} FROM delivery_events ${where} ORDER BY timestamp DESC LIMIT $${params.length}`, params);
      reply.hijack();
      const raw = reply.raw;
      raw.setHeader('Content-Type', 'text/csv');
      raw.setHeader('Content-Disposition', `attachment; filename="srmta-logs-${Date.now()}.csv"`);
      raw.write(`${CSV_COLUMNS.join(',')}\n`);
      for (const row of result.rows) raw.write(`${CSV_COLUMNS.map((c) => csvEscape(row[c])).join(',')}\n`);
      raw.end();
    } catch (err) {
      fastify.log.error({ err }, 'logs_export_query_error');
      return reply.code(500).send({ error: 'Internal server error' });
    }
  });

  fastify.get('/api/logs', { preHandler: [fastify.requireRole(['admin', 'operator'])], schema: { querystring: querySchema } }, async (request, reply) => {
    const page = Math.max(1, Number.parseInt(request.query.page, 10) || 1);
    const per_page = Math.min(Math.max(1, Number.parseInt(request.query.per_page, 10) || 50), 200);
    const offset = (page - 1) * per_page;
    const { where, params } = buildLogFilters(request.query);
    try {
      const dataParams = [...params, per_page, offset];
      const dataSql = `SELECT timestamp, message_id, sender, recipient, remote_mx, response_code, response_text, ip_used, tls_status, retry_count, dkim_status, processing_latency_ms, status FROM delivery_events ${where} ORDER BY timestamp DESC LIMIT $${dataParams.length - 1} OFFSET $${dataParams.length}`;
      const countSql = `SELECT COUNT(*)::bigint AS total FROM delivery_events ${where}`;
      const [dataResult, countResult] = await Promise.all([pool.query(dataSql, dataParams), pool.query(countSql, params)]);
      const total = Number(countResult.rows[0]?.total || 0);
      return { data: dataResult.rows, pagination: { page, per_page, total, total_pages: Math.ceil(total / per_page) } };
    } catch (err) {
      fastify.log.error({ err }, 'logs_query_error');
      return reply.code(500).send({ error: 'Internal server error' });
    }
  });
}

function queueRoutes() {
  fastify.get('/api/queue/stats', { preHandler: [fastify.authenticate] }, async () => {
    const spoolNames = ['incoming', 'active', 'deferred', 'retry', 'dead_letter', 'failed'];
    const spools = {};
    let totalDepth = 0;
    for (const name of spoolNames) {
      const result = await countSpool(name);
      spools[name] = result;
      totalDepth += result.depth;
    }
    return { spools, total_depth: totalDepth, processing_rate: 0 };
  });

  fastify.post('/api/queue/flush', {
    preHandler: [fastify.requireRole(['admin'])],
    schema: { body: { type: 'object', required: ['spool'], additionalProperties: false, properties: { spool: { type: 'string', enum: ['incoming', 'active', 'deferred', 'retry', 'dead_letter', 'failed'] } } } },
  }, async (request, reply) => {
    const { spool } = request.body;
    const dirName = spool === 'dead_letter' ? 'dead-letter' : spool;
    const spoolPath = path.join(config.spoolDir, dirName);
    let deleted = 0;
    try {
      const shardDirs = await fs.promises.readdir(spoolPath);
      for (const sd of shardDirs) {
        const sdPath = path.join(spoolPath, sd);
        const files = await fs.promises.readdir(sdPath).catch(() => []);
        for (const f of files) {
          await fs.promises.unlink(path.join(sdPath, f)).catch(() => {});
          deleted++;
        }
      }
    } catch (err) {
      fastify.log.error({ err }, 'queue_flush_error');
      return reply.code(500).send({ error: 'Flush failed', detail: err.message });
    }
    return { flushed: spool, deleted };
  });
}

function domainRoutes() {
  fastify.get('/api/domains/stats', { preHandler: [fastify.authenticate] }, async () => {
    const domainCounts = new Map();
    const spoolPath = path.join(config.spoolDir, 'active');
    try {
      const shardDirs = await fs.promises.readdir(spoolPath);
      for (const sd of shardDirs) {
        const sdPath = path.join(spoolPath, sd);
        const files = await fs.promises.readdir(sdPath).catch(() => []);
        for (const f of files) {
          if (!f.endsWith('.meta')) continue;
          try {
            const raw = await fs.promises.readFile(path.join(sdPath, f), 'utf8');
            const meta = JSON.parse(raw);
            if (meta.domain) domainCounts.set(meta.domain, (domainCounts.get(meta.domain) || 0) + 1);
          } catch {}
        }
      }
    } catch {}
    const domains = [...domainCounts.entries()]
      .map(([domain, queue_depth]) => ({ domain, queue_depth }))
      .sort((a, b) => b.queue_depth - a.queue_depth);
    return { domains };
  });

  fastify.get('/api/ips', { preHandler: [fastify.authenticate] }, async (request, reply) => {
    try {
      const result = await pool.query(
        `SELECT DISTINCT ON (ip_address) ip_address, health_score, total_sent, rate_4xx, rate_5xx, timeout_rate, tls_fail_rate, disabled, recorded_at FROM ip_health_log ORDER BY ip_address, recorded_at DESC`
      );
      return { ips: result.rows };
    } catch (err) {
      fastify.log.error({ err }, 'ips_query_error');
      return reply.code(500).send({ error: 'Internal server error' });
    }
  });

}

function websocketRoutes() {
  fastify.get('/ws', { websocket: true, preHandler: [fastify.authenticate] }, (socket) => {
    socket.on('message', (message) => {
      try {
        const data = JSON.parse(message.toString());
        if (data.type === 'subscribe' && typeof data.channel === 'string' && data.channel.length <= 64) {
          socket.send(JSON.stringify({ type: 'subscribed', channel: data.channel }));
        } else {
          socket.send(JSON.stringify({ type: 'error', message: 'Invalid subscription request' }));
        }
      } catch (e) {
        fastify.log.warn({ err: e }, 'ws_invalid_json');
        socket.send(JSON.stringify({ type: 'error', message: 'Invalid JSON' }));
      }
    });

    const interval = setInterval(async () => {
      try {
        const spoolNames = ['incoming', 'active', 'deferred', 'retry', 'dead_letter', 'failed'];
        const spools = {};
        let totalDepth = 0;
        for (const name of spoolNames) {
          const result = await countSpool(name);
          spools[name] = result.depth;
          totalDepth += result.depth;
        }
        socket.send(JSON.stringify({
          type: 'metrics_update',
          timestamp: new Date().toISOString(),
          data: { queue_depth: totalDepth, spools },
        }));
      } catch (err) {
        fastify.log.warn({ err }, 'ws_metrics_error');
      }
    }, 5000);

    socket.on('close', () => clearInterval(interval));
  });
}

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

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  fastify.log.info({ signal }, 'shutting_down');
  try { await fastify.close(); } catch (err) { fastify.log.error({ err }, 'fastify_close_error'); }
  try { await pool.end(); } catch (err) { fastify.log.error({ err }, 'pg_pool_close_error'); }
  process.exit(0);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

start();
