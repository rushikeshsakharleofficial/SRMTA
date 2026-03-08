/**
 * SRMTA Admin API Server
 * Fastify-based REST API with JWT authentication, RBAC, rate limiting,
 * WebSocket live updates, and full CRUD for mail platform management.
 */

const fastify = require('fastify')({ logger: true });

// ── Configuration ─────────────────────────────────────────────────────────
const config = {
  port: parseInt(process.env.API_PORT || '3000'),
  host: process.env.API_HOST || '0.0.0.0',
  jwtSecret: process.env.JWT_SECRET || 'change-me-in-production',
  db: {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432'),
    user: process.env.DB_USER || 'srmta',
    password: process.env.DB_PASSWORD || 'srmta_secret',
    database: process.env.DB_NAME || 'srmta',
  },
  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379',
  },
};

// ── Register Plugins ──────────────────────────────────────────────────────
async function registerPlugins() {
  // CORS
  await fastify.register(require('@fastify/cors'), {
    origin: true,
    credentials: true,
  });

  // JWT Authentication
  await fastify.register(require('@fastify/jwt'), {
    secret: config.jwtSecret,
    sign: { expiresIn: '24h' },
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
    uptime: process.uptime(),
  }));
}

// ── Auth Routes ───────────────────────────────────────────────────────────
function authRoutes() {
  // POST /api/auth/login
  fastify.post('/api/auth/login', async (request, reply) => {
    const { username, password } = request.body || {};
    if (!username || !password) {
      return reply.code(400).send({ error: 'Username and password required' });
    }

    // TODO: Validate against database
    // For now, accept admin/admin for development
    if (username === 'admin' && password === 'admin') {
      const token = fastify.jwt.sign({
        id: '1',
        username: 'admin',
        role: 'admin',
      });
      return { token, user: { id: '1', username: 'admin', role: 'admin' } };
    }

    return reply.code(401).send({ error: 'Invalid credentials' });
  });

  // GET /api/auth/me
  fastify.get('/api/auth/me', { preHandler: [fastify.authenticate] }, async (request) => {
    return { user: request.user };
  });
}

// ── Send Routes ───────────────────────────────────────────────────────────
function sendRoutes() {
  // POST /api/send — Send a single email
  fastify.post('/api/send', { preHandler: [fastify.authenticate] }, async (request, reply) => {
    const { from, to, subject, body, html } = request.body || {};

    if (!from || !to || !subject) {
      return reply.code(400).send({ error: 'from, to, and subject are required' });
    }

    const messageId = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    // TODO: Enqueue to SMTP engine via Redis
    return {
      message_id: messageId,
      status: 'queued',
      queued_at: new Date().toISOString(),
    };
  });

  // POST /api/bulk — Send bulk emails
  fastify.post('/api/bulk', { preHandler: [fastify.authenticate] }, async (request, reply) => {
    const { messages } = request.body || {};

    if (!Array.isArray(messages) || messages.length === 0) {
      return reply.code(400).send({ error: 'messages array is required' });
    }

    const results = messages.map((msg, idx) => ({
      index: idx,
      message_id: `${Date.now()}-${idx}-${Math.random().toString(36).substr(2, 9)}`,
      status: 'queued',
    }));

    return { total: messages.length, results };
  });

  // POST /api/schedule — Schedule an email
  fastify.post('/api/schedule', { preHandler: [fastify.authenticate] }, async (request, reply) => {
    const { from, to, subject, body, send_at } = request.body || {};

    if (!from || !to || !subject || !send_at) {
      return reply.code(400).send({ error: 'from, to, subject, and send_at are required' });
    }

    const messageId = `sched-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

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
  fastify.get('/api/status/:id', { preHandler: [fastify.authenticate] }, async (request) => {
    const { id } = request.params;

    // TODO: Query PostgreSQL for message status
    return {
      message_id: id,
      status: 'delivered',
      sender: 'sender@example.com',
      recipient: 'recipient@example.com',
      queued_at: new Date().toISOString(),
      delivered_at: new Date().toISOString(),
      retry_count: 0,
      response_code: 250,
      response_text: '2.0.0 OK',
    };
  });
}

// ── Metrics Routes ────────────────────────────────────────────────────────
function metricsRoutes() {
  // GET /api/metrics
  fastify.get('/api/metrics', { preHandler: [fastify.authenticate] }, async () => {
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

    const crypto = require('crypto');
    const bodyStr = JSON.stringify(request.body);
    const expectedSig = crypto
      .createHmac('sha256', config.jwtSecret)
      .update(bodyStr)
      .digest('hex');

    if (signature !== `sha256=${expectedSig}`) {
      return reply.code(401).send({ error: 'Invalid webhook signature' });
    }

    // Process webhook
    const { event_type, data } = request.body || {};
    fastify.log.info({ event_type, data }, 'Webhook received');

    return { status: 'received' };
  });
}

// ── Log Export Routes ─────────────────────────────────────────────────────
function logRoutes() {
  // GET /api/logs/export
  fastify.get('/api/logs/export', { preHandler: [fastify.authenticate] }, async (request, reply) => {
    const { from, to, status, sender, limit } = request.query;

    // TODO: Query PostgreSQL for delivery events and stream as CSV
    reply.header('Content-Type', 'text/csv');
    reply.header('Content-Disposition', `attachment; filename="srmta-logs-${Date.now()}.csv"`);

    return 'timestamp,message_id,sender,recipient,remote_mx,response_code,response_text,ip_used,tls_status,retry_count,dkim_status,processing_latency_ms,status\n';
  });

  // GET /api/logs — Paginated log viewer
  fastify.get('/api/logs', { preHandler: [fastify.authenticate] }, async (request) => {
    const { page = 1, per_page = 50, status, sender, recipient } = request.query;

    // TODO: Query PostgreSQL
    return {
      data: [],
      pagination: {
        page: parseInt(page),
        per_page: parseInt(per_page),
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
  fastify.get('/ws', { websocket: true }, (socket, request) => {
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
