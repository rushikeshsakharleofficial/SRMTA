/**
 * SRMTA Admin API Server
 * Fastify-based REST API with JWT authentication, RBAC, rate limiting,
 * WebSocket live updates, and full CRUD for mail platform management.
 */

const fastify = require('fastify')({ logger: true });

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

// ── Utils ─────────────────────────────────────────────────────────────────
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
      // TODO: Replace with actual DB query using config.db pool
      // const result = await db.query('SELECT id, username, password_hash, role FROM api_users WHERE username = $1', [username]);
      // const user = result.rows[0];
      // For now, reject all logins until DB auth is configured
      const user = null;
      if (!user) {
        return reply.code(401).send({ error: 'Invalid credentials' });
      }
      const valid = await bcrypt.compare(password, user.password_hash);
      if (!valid) {
        return reply.code(401).send({ error: 'Invalid credentials' });
      }
      const token = fastify.jwt.sign({
        id: user.id,
        username: user.username,
        role: user.role,
      });
      return { token, user: { id: user.id, username: user.username, role: user.role } };
    } catch (err) {
      fastify.log.error(err, 'Login error');
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
  // IDOR Fix: Add ownership check (placeholder)
  fastify.get('/api/status/:id', { preHandler: [fastify.authenticate] }, async (request, reply) => {
    const { id } = request.params;

    // TODO: Query PostgreSQL for message status
    const message = {
      message_id: id,
      user_id: 'some-user-id', // This should come from DB
      status: 'delivered',
      sender: 'sender@example.com',
      recipient: 'recipient@example.com',
      queued_at: new Date().toISOString(),
      delivered_at: new Date().toISOString(),
      retry_count: 0,
      response_code: 250,
      response_text: '2.0.0 OK',
    };

    // IDOR Check: Ensure user owns the message or is admin
    if (request.user.role !== 'admin' && message.user_id !== request.user.id) {
      return reply.code(403).send({ error: 'Forbidden', message: 'Access denied to this message status' });
    }

    return message;
  });
}

// ── Metrics Routes ────────────────────────────────────────────────────────
function metricsRoutes() {
  // GET /api/metrics
  // RBAC Fix: Restrict to admin/operator
  fastify.get('/api/metrics', {
    preHandler: [fastify.requireRole(['admin', 'operator'])],
  }, async () => {
    // TODO: Query real metrics from SMTP engine
    return {
      timestamp: new Date().toISOString(),
      delivery: {
        total_sent: 0,
        delivered: 0,
        bounced: 0,
        deferred: 0,
        failed: 0,
        success_rate: 0,
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
        avg_latency_ms: 0,
      },
      ip_pool: [],
    };
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
function logRoutes() {
  // GET /api/logs/export
  // RBAC Fix: Restrict to admin/operator
  fastify.get('/api/logs/export', {
    preHandler: [fastify.requireRole(['admin', 'operator'])],
  }, async (request, reply) => {
    const limit = Math.min(Number.parseInt(request.query.limit) || 10000, 50000);

    // TODO: Query PostgreSQL for delivery events and stream as CSV
    reply.header('Content-Type', 'text/csv');
    reply.header('Content-Disposition', `attachment; filename="srmta-logs-${Date.now()}.csv"`);

    return 'timestamp,message_id,sender,recipient,remote_mx,response_code,response_text,ip_used,tls_status,retry_count,dkim_status,processing_latency_ms,status\n';
  });

  // GET /api/logs — Paginated log viewer
  // RBAC Fix: Restrict to admin/operator
  fastify.get('/api/logs', {
    preHandler: [fastify.requireRole(['admin', 'operator'])],
  }, async (request) => {
    const page = Math.max(1, Number.parseInt(request.query.page) || 1);
    const per_page = Math.min(Math.max(1, Number.parseInt(request.query.per_page) || 50), 200);

    // TODO: Query PostgreSQL
    return {
      data: [],
      pagination: {
        page,
        per_page,
        total: 0,
        total_pages: 0,
      },
    };
  });
}

// ── Queue Management Routes ───────────────────────────────────────────────
function queueRoutes() {
  // GET /api/queue/stats
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
  fastify.get('/api/ips', { preHandler: [fastify.authenticate] }, async () => {
    return { ips: [] };
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

start();
