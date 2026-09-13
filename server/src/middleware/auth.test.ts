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

function fakeRequest(headers: Record<string, string> = {}): {
  header: (name: string) => string | undefined;
  moduleAdmin?: unknown;
} {
  const lower = Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value])
  );
  return { header: (name: string) => lower[name.toLowerCase()] };
}

function basicAuthHeader(username: string, password: string): string {
  return `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
}

test('standalone basic auth rejects a request with no Authorization header', () => {
  const req = fakeRequest();
  const res = fakeResponse();
  let called = false;
  requireAuth(req as never, res as never, () => {
    called = true;
  });
  assert.equal(called, false);
  assert.equal(res.statusCode, 401);
  assert.equal(res.headers['WWW-Authenticate'], 'Basic realm="Robin Tools", charset="UTF-8"');
});

test('standalone basic auth rejects the wrong password', () => {
  const req = fakeRequest({ authorization: basicAuthHeader('admin', 'wrong-password') });
  const res = fakeResponse();
  let called = false;
  requireAuth(req as never, res as never, () => {
    called = true;
  });
  assert.equal(called, false);
  assert.equal(res.statusCode, 401);
});

test('standalone basic auth rejects the wrong username', () => {
  const req = fakeRequest({
    authorization: basicAuthHeader('someone-else', 'correct-horse-battery-staple'),
  });
  const res = fakeResponse();
  let called = false;
  requireAuth(req as never, res as never, () => {
    called = true;
  });
  assert.equal(called, false);
  assert.equal(res.statusCode, 401);
});

test('standalone basic auth accepts the configured credentials', () => {
  const req = fakeRequest({
    authorization: basicAuthHeader('admin', 'correct-horse-battery-staple'),
  });
  const res = fakeResponse();
  let called = false;
  requireAuth(req as never, res as never, () => {
    called = true;
  });
  assert.equal(called, true);
  assert.equal(res.statusCode, null);
  assert.deepEqual((req as { moduleAdmin?: { role: string } }).moduleAdmin?.role, 'admin');
});
