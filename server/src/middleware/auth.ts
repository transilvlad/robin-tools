import { createHash, timingSafeEqual } from 'node:crypto';
import bcrypt from 'bcryptjs';
import type { NextFunction, Request, Response } from 'express';
import { config } from '../config.js';

// Constant-time comparison: hashing first guarantees equal-length buffers so
// timingSafeEqual never short-circuits on a length mismatch, avoiding a
// timing side-channel that could otherwise leak information about the secret.
function safeSecretEquals(a: string, b: string): boolean {
  const hashedA = createHash('sha256').update(a).digest();
  const hashedB = createHash('sha256').update(b).digest();
  return timingSafeEqual(hashedA, hashedB);
}

export type ModuleAdminRole = 'viewer' | 'editor' | 'admin';

export interface ModuleAdminContext {
  adminId: number;
  name: string;
  email: string;
  role: ModuleAdminRole;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace -- required by Express's own Request augmentation pattern
  namespace Express {
    interface Request {
      moduleAdmin?: ModuleAdminContext;
    }
  }
}

// Standalone mode has exactly one operator account, so it is modeled as a
// fixed admin context rather than a row looked up from a database.
const STANDALONE_ADMIN: ModuleAdminContext = {
  adminId: 1,
  name: 'Robin Tools',
  email: 'standalone@robin-tools.local',
  role: 'admin',
};

// Basic Auth has no built-in brute-force protection, so failed login
// attempts are throttled per source IP: after MAX_FAILED_ATTEMPTS failures
// within the window, further attempts are rejected with 429 until the
// window resets, regardless of whether the credentials would be correct.
const LOGIN_ATTEMPT_WINDOW_MS = 15 * 60_000;
const MAX_FAILED_ATTEMPTS = 10;
const failedAttempts = new Map<string, { count: number; resetAt: number }>();

function clientIp(req: Request): string {
  return req.ip ?? req.socket?.remoteAddress ?? 'unknown';
}

function isLockedOut(ip: string): number | null {
  const bucket = failedAttempts.get(ip);
  if (!bucket) {
    return null;
  }
  if (bucket.resetAt <= Date.now()) {
    failedAttempts.delete(ip);
    return null;
  }
  if (bucket.count >= MAX_FAILED_ATTEMPTS) {
    return bucket.resetAt;
  }
  return null;
}

function recordFailedAttempt(ip: string): void {
  const now = Date.now();
  const current = failedAttempts.get(ip);
  const bucket =
    !current || current.resetAt <= now
      ? { count: 0, resetAt: now + LOGIN_ATTEMPT_WINDOW_MS }
      : current;
  bucket.count += 1;
  failedAttempts.set(ip, bucket);
}

function clearFailedAttempts(ip: string): void {
  failedAttempts.delete(ip);
}

function requireStandaloneAuth(req: Request, res: Response, next: NextFunction): void {
  if (config.standaloneAuth.mode === 'none') {
    req.moduleAdmin = STANDALONE_ADMIN;
    next();
    return;
  }

  const ip = clientIp(req);

  const unauthorized = () => {
    recordFailedAttempt(ip);
    res.set('WWW-Authenticate', 'Basic realm="Robin Tools", charset="UTF-8"');
    res.status(401).json({
      success: false,
      error: 'Authentication required',
    });
  };

  const lockedUntil = isLockedOut(ip);
  if (lockedUntil !== null) {
    res.set('Retry-After', String(Math.max(1, Math.ceil((lockedUntil - Date.now()) / 1000))));
    res.status(429).json({
      success: false,
      error: 'Too many failed login attempts. Try again later.',
    });
    return;
  }

  const header = (req.header('authorization') ?? '').trim();
  const schemeEnd = header.indexOf(' ');
  if (schemeEnd <= 0 || header.slice(0, schemeEnd).toLowerCase() !== 'basic') {
    unauthorized();
    return;
  }

  const encodedCredentials = header.slice(schemeEnd + 1).trimStart();
  if (!encodedCredentials) {
    unauthorized();
    return;
  }

  let decoded: string;
  try {
    decoded = Buffer.from(encodedCredentials, 'base64').toString('utf8');
  } catch {
    unauthorized();
    return;
  }

  const separatorIndex = decoded.indexOf(':');
  if (separatorIndex < 0) {
    unauthorized();
    return;
  }

  const username = decoded.slice(0, separatorIndex);
  const password = decoded.slice(separatorIndex + 1);

  if (!config.standaloneAuth.passwordHash) {
    // Misconfiguration: basic auth requested but no hash configured. Fail
    // closed rather than silently accepting any credentials.
    unauthorized();
    return;
  }

  if (
    !safeSecretEquals(username, config.standaloneAuth.username) ||
    !bcrypt.compareSync(password, config.standaloneAuth.passwordHash)
  ) {
    unauthorized();
    return;
  }

  clearFailedAttempts(ip);
  req.moduleAdmin = STANDALONE_ADMIN;
  next();
}

function requireModuleAuth(req: Request, res: Response, next: NextFunction): void {
  const secret = req.header('x-robin-module-secret');
  if (!secret || !safeSecretEquals(secret, config.proxySecret)) {
    res.status(401).json({
      success: false,
      error: 'Unauthorized module request',
    });
    return;
  }

  const role = req.header('x-robin-admin-role');
  const adminId = Number.parseInt(req.header('x-robin-admin-id') || '0', 10);
  if (
    !role ||
    !['viewer', 'editor', 'admin'].includes(role) ||
    !Number.isFinite(adminId) ||
    adminId <= 0
  ) {
    res.status(401).json({
      success: false,
      error: 'Missing admin context',
    });
    return;
  }

  req.moduleAdmin = {
    adminId,
    name: req.header('x-robin-admin-name') || 'Robin Admin',
    email: req.header('x-robin-admin-email') || 'unknown@local',
    role: role as ModuleAdminRole,
  };
  next();
}

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (config.deploymentMode === 'standalone') {
    requireStandaloneAuth(req, res, next);
    return;
  }

  requireModuleAuth(req, res, next);
}
