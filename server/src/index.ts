import express from 'express';
import rateLimit from 'express-rate-limit';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { closePool, query, testConnection } from './db/connection.js';
import { logger } from './logger.js';
import { config } from './config.js';
import robinToolsRoutes from './routes/robin-tools.js';
import {
  startSenderEnrichmentCacheSweep,
  stopSenderEnrichmentCacheSweep,
} from './services/sender-enrichment.js';

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const STATIC_FALLBACK_RATE_LIMIT_WINDOW_MS = 60_000;
const STATIC_FALLBACK_RATE_LIMIT_MAX_REQUESTS = 300;
const staticFallbackRateLimiter = rateLimit({
  windowMs: STATIC_FALLBACK_RATE_LIMIT_WINDOW_MS,
  limit: STATIC_FALLBACK_RATE_LIMIT_MAX_REQUESTS,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many Robin Tools requests. Try again shortly.',
  },
});

function assertProductionSecrets() {
  if (config.nodeEnv !== 'production') {
    return;
  }

  if (
    !config.proxySecret ||
    config.proxySecret === 'dev-secret-change-in-production' ||
    config.proxySecret === 'change-me-in-production'
  ) {
    throw new Error('Refusing to start Robin Tools with a missing/default MODULE_PROXY_SECRET.');
  }

  if (!config.postgres.password || config.postgres.password === 'robin') {
    throw new Error('Refusing to start Robin Tools with a missing/default database password.');
  }

  if (
    config.deploymentMode === 'standalone' &&
    config.standaloneAuth.mode === 'basic' &&
    !config.standaloneAuth.passwordHash
  ) {
    throw new Error(
      'Refusing to start Robin Tools in standalone mode with basic auth enabled but no ROBIN_TOOLS_AUTH_PASSWORD_HASH set.'
    );
  }
}

app.use(express.json({ limit: '512kb' }));
app.use(express.urlencoded({ extended: true, limit: '512kb' }));

app.use((req, res, next) => {
  const startedAt = performance.now();

  res.on('finish', () => {
    const duration = Math.round(performance.now() - startedAt);
    const meta = {
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration,
    };

    if (duration >= 1000 || res.statusCode >= 500) {
      logger.warn('Robin Tools request completed slowly or with error', meta);
      return;
    }

    logger.debug('Robin Tools request completed', meta);
  });

  next();
});

app.use((_req, res, next) => {
  if (config.nodeEnv === 'production') {
    const sendJson = res.json.bind(res);
    res.json = ((body: unknown) => {
      if (res.statusCode >= 500 && body && typeof body === 'object' && 'error' in body) {
        return sendJson({ ...(body as Record<string, unknown>), error: 'Internal server error' });
      }
      return sendJson(body);
    }) as typeof res.json;
  }
  next();
});

app.get('/health', async (_req, res) => {
  const databaseReady = await testConnection();
  res.status(databaseReady ? 200 : 503).json({
    status: databaseReady ? 'ok' : 'unavailable',
    module: 'robin-tools',
    checks: { database: databaseReady ? 'ok' : 'unavailable' },
    timestamp: new Date().toISOString(),
  });
});

if (config.deploymentMode === 'standalone') {
  // Standalone deployments have no host proxy, so the API is mounted under
  // /api and this process also serves the built frontend directly.
  app.use('/api', robinToolsRoutes);

  const staticDir = process.env.STATIC_DIR ?? path.join(currentDir, '../public');
  if (fs.existsSync(staticDir)) {
    app.use(express.static(staticDir, { index: false }));
    app.get('*', staticFallbackRateLimiter, (_req, res) => {
      res.sendFile(path.join(staticDir, 'index.html'));
    });
  } else {
    logger.warn('Standalone static directory not found; frontend will not be served', {
      staticDir,
    });
  }

  app.use((_req, res) => {
    res.status(404).json({ success: false, error: 'Not found' });
  });
} else {
  app.use('/', robinToolsRoutes);
}

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  logger.error('Unhandled Robin Tools error', {
    error: err.message,
    ...(config.nodeEnv === 'development' ? { stack: err.stack } : {}),
  });
  res.status(500).json({
    success: false,
    error: config.nodeEnv === 'development' ? err.message : 'Internal server error',
  });
});

async function ensureHistorySchema() {
  await query('CREATE SCHEMA IF NOT EXISTS robin_tools_module');
  await query(`
    CREATE TABLE IF NOT EXISTS robin_tools_module.tool_settings (
      key TEXT PRIMARY KEY,
      value_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await query(`
    CREATE TABLE IF NOT EXISTS robin_tools_module.check_history (
      id SERIAL PRIMARY KEY,
      admin_id INTEGER NOT NULL,
      issue_id INTEGER NULL,
      subject_value TEXT NULL,
      tool_kind VARCHAR(32) NOT NULL,
      target_type VARCHAR(16) NOT NULL,
      target_value TEXT NOT NULL,
      selector VARCHAR(255) NULL,
      status VARCHAR(24) NOT NULL,
      summary TEXT NULL,
      result_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await query(`
    ALTER TABLE robin_tools_module.check_history
      ADD COLUMN IF NOT EXISTS subject_value TEXT NULL
  `);
  await query(`
    CREATE INDEX IF NOT EXISTS idx_robin_tools_check_history_admin_target
      ON robin_tools_module.check_history (admin_id, tool_kind, target_type, target_value, created_at DESC)
  `);
  await query(`
    CREATE INDEX IF NOT EXISTS idx_robin_tools_check_history_admin_issue
      ON robin_tools_module.check_history (admin_id, issue_id, created_at DESC)
  `);
  await query(`
    CREATE INDEX IF NOT EXISTS idx_robin_tools_check_history_admin_issue_subject
      ON robin_tools_module.check_history (admin_id, issue_id, subject_value, created_at DESC)
  `);
}

async function shutdown() {
  stopSenderEnrichmentCacheSweep();
  await closePool();
  process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

async function start() {
  assertProductionSecrets();

  if (!(await testConnection())) {
    process.exit(1);
  }

  await ensureHistorySchema();
  startSenderEnrichmentCacheSweep();

  app.listen(config.port, () => {
    logger.info(`Robin Tools backend listening on ${config.port}`, {
      deploymentMode: config.deploymentMode,
      ...(config.deploymentMode === 'standalone' ? { authMode: config.standaloneAuth.mode } : {}),
    });
  });
}

void start();
