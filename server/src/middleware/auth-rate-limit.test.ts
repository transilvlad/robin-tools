import assert from 'node:assert/strict';
import test from 'node:test';
import bcrypt from 'bcryptjs';

// Module mocking / env vars must be set before config.js (and anything that
// imports it) is loaded, so this runs before the dynamic import below.
process.env.MODULE_PROXY_SECRET = 'test-secret';
process.env.NODE_ENV = 'test';
process.env.DEPLOYMENT_MODE = 'standalone';
process.env.ROBIN_TOOLS_AUTH_MODE = 'basic';
process.env.ROBIN_TOOLS_AUTH_USERNAME = 'admin';
process.env.ROBIN_TOOLS_AUTH_PASSWORD_HASH = bcrypt.hashSync('correct-horse-battery-staple', 10);

const { requireAuth } = await import('./auth.js');

interface FakeResponse {
  statusCode: number | null;
  headers: Record<string, string>;
  body: unknown;
  set(name: string, value: string): FakeResponse;
  status(code: number): FakeResponse;
  json(payload: unknown): FakeResponse;
}

function fakeResponse(): FakeResponse {
  const res: FakeResponse = {
    statusCode: null,
    headers: {},
    body: undefined,
    set(name, value) {
      res.headers[name] = value;
      return res;
    },
    status(code) {
      res.statusCode = code;
      return res;
    },
    json(payload) {
      res.body = payload;
      return res;
    },
  };
  return res;
}

function fakeRequest(
  ip: string,
  headers: Record<string, string> = {}
): { ip: string; header: (name: string) => string | undefined; moduleAdmin?: unknown } {
  const lower = Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value])
  );
  return { ip, header: (name: string) => lower[name.toLowerCase()] };
}

function basicAuthHeader(username: string, password: string): string {
  return `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
}

function attempt(ip: string, password: string): FakeResponse {
  const req = fakeRequest(ip, { authorization: basicAuthHeader('admin', password) });
  const res = fakeResponse();
  requireAuth(req as never, res as never, () => {});
  return res;
}

test('standalone basic auth locks out an IP after repeated failed attempts', () => {
  const ip = '203.0.113.10';
  let lastRes: FakeResponse | undefined;
  for (let i = 0; i < 10; i += 1) {
    lastRes = attempt(ip, 'wrong-password');
    assert.equal(lastRes.statusCode, 401);
  }

  // 11th attempt within the window is locked out even with correct
  // credentials, because brute-force protection blocks by source IP, not by
  // whether the guessed password happens to be right.
  const lockedRes = attempt(ip, 'correct-horse-battery-staple');
  assert.equal(lockedRes.statusCode, 429);
  assert.ok(lockedRes.headers['Retry-After']);
});

test('standalone basic auth does not lock out unrelated IPs', () => {
  const attackerIp = '203.0.113.20';
  for (let i = 0; i < 10; i += 1) {
    attempt(attackerIp, 'wrong-password');
  }

  const otherIp = '198.51.100.5';
  const res = attempt(otherIp, 'correct-horse-battery-staple');
  assert.equal(res.statusCode, null);
});

test('a successful login clears prior failed attempts for that IP', () => {
  const ip = '203.0.113.30';
  for (let i = 0; i < 5; i += 1) {
    const res = attempt(ip, 'wrong-password');
    assert.equal(res.statusCode, 401);
  }

  const successRes = attempt(ip, 'correct-horse-battery-staple');
  assert.equal(successRes.statusCode, null);

  // Failures reset after success, so this single follow-up failure should
  // not trigger lockout.
  const followUp = attempt(ip, 'wrong-password');
  assert.equal(followUp.statusCode, 401);
});
