import assert from 'node:assert/strict';
import test, { after, before, mock } from 'node:test';
import express from 'express';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';

// Module mocking must happen before the router (and anything it imports) is
// loaded, so these env vars and mock.module() calls run first.
process.env.MODULE_PROXY_SECRET = 'test-secret';
process.env.NODE_ENV = 'test';

mock.module('../db/connection.js', {
  namedExports: {
    query: async () => ({ rows: [], rowCount: 0 }),
  },
});

const { default: robinToolsRouter } = await import('./robin-tools.js');

let server: Server;
let baseUrl: string;

before(async () => {
  const app = express();
  app.use(express.json());
  app.use('/', robinToolsRouter);
  server = app.listen(0);
  await new Promise<void>((resolve) => server.once('listening', resolve));
  const address = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

type Role = 'viewer' | 'editor' | 'admin' | null;

function authHeaders(role: Role, adminId: string, includeSecret: boolean): Record<string, string> {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (includeSecret) {
    headers['x-robin-module-secret'] = 'test-secret';
  }
  if (role) {
    headers['x-robin-admin-role'] = role;
    headers['x-robin-admin-id'] = adminId;
  }
  return headers;
}

async function call(
  method: string,
  path: string,
  opts: { role?: Role; adminId?: string; includeSecret?: boolean; body?: unknown } = {}
) {
  // Distinguish "role not specified" (default to admin) from an explicit
  // `role: null` (send no role/adminId headers at all) — a `??` fallback
  // would incorrectly turn an explicit null back into 'admin'.
  const role = 'role' in opts ? opts.role! : 'admin';
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: authHeaders(role, opts.adminId ?? '1', opts.includeSecret ?? true),
    body: method === 'GET' || method === 'DELETE' ? undefined : JSON.stringify(opts.body ?? {}),
  });
  const body = await response.json().catch(() => null);
  return { status: response.status, body };
}

interface RouteSpec {
  method: string;
  path: string;
  /** Minimum role the route should require. */
  role: 'viewer' | 'editor' | 'admin';
}

// Every route registered in robin-tools.ts, with the role its handler is
// mounted behind (bare = the router-wide `requireViewer` gate). Path params
// use realistic placeholder values so requests reach real handler logic
// instead of failing route-pattern matching.
const ROUTES: RouteSpec[] = [
  { method: 'GET', path: '/context', role: 'viewer' },
  { method: 'GET', path: '/settings', role: 'viewer' },
  { method: 'PUT', path: '/settings', role: 'admin' },
  { method: 'POST', path: '/reputation/rbl/run', role: 'editor' },
  { method: 'POST', path: '/reputation/dbl/run', role: 'editor' },
  { method: 'POST', path: '/mail-tests/message-analysis/run', role: 'editor' },
  { method: 'POST', path: '/mail-tests/mail-server-test/run', role: 'editor' },
  { method: 'GET', path: '/checks/recent', role: 'viewer' },
  {
    method: 'GET',
    path: '/checks/history?toolKind=spf&targetType=domain&targetValue=example.com',
    role: 'viewer',
  },
  { method: 'DELETE', path: '/checks/history/1', role: 'editor' },
  { method: 'DELETE', path: '/checks/history', role: 'editor' },
  { method: 'POST', path: '/checks/run', role: 'editor' },
  { method: 'POST', path: '/domains/bulk-check', role: 'editor' },
  { method: 'POST', path: '/ips/bulk-check', role: 'editor' },
];

const ROLE_RANK: Record<'viewer' | 'editor' | 'admin', number> = { viewer: 1, editor: 2, admin: 3 };

test('every declared route is reachable and correctly role-gated', async (t) => {
  for (const route of ROUTES) {
    await t.test(`${route.method} ${route.path}`, async () => {
      const noSecret = await call(route.method, route.path, { includeSecret: false });
      assert.equal(
        noSecret.status,
        401,
        'must reject a request with no module proxy secret at all'
      );

      const noIdentity = await call(route.method, route.path, { role: null });
      assert.equal(
        noIdentity.status,
        401,
        'must reject a request with the secret but no admin identity headers'
      );

      if (route.role !== 'viewer') {
        // Pick a role one step below what's required — viewer for an editor
        // route, editor for an admin route — and confirm it's refused.
        const insufficient: Role = route.role === 'admin' ? 'editor' : 'viewer';
        const denied = await call(route.method, route.path, { role: insufficient });
        assert.equal(
          denied.status,
          403,
          `must reject role "${insufficient}" (below required "${route.role}")`
        );
      }

      const allowed = await call(route.method, route.path, { role: route.role });
      // This is the regression check for the bug this suite was written to
      // catch: a stale hardcoded path-allowlist previously 404'd every route
      // added after it
      // even though a handler existed further down the file. A route that's
      // reachable may still legitimately 400 (bad input) or 404 for a
      // missing RESOURCE, but never with this exact routing-layer message.
      if (allowed.status === 404) {
        assert.notEqual(
          (allowed.body as { error?: string } | null)?.error,
          'Robin Tools endpoint not found',
          'route exists in this file but was not reachable — check the router for a stale path allowlist'
        );
      }
      assert.ok(ROLE_RANK[route.role] >= 1, 'sanity check: route table role is well-formed');
    });
  }
});

test('settings PUT sanitizes and caps values before persisting', async () => {
  const result = await call('PUT', '/settings', {
    role: 'admin',
    body: {
      settings: {
        timeoutMs: 999_999, // above the 30s cap
        concurrency: 0, // below the 1 minimum
        serverPorts: [25, 25, 99999, -1, 587], // dedup + drop out-of-range
        resolvers: ['not-an-ip', '203.0.113.1'],
      },
    },
  });

  assert.equal(result.status, 200);
  const settings = (result.body as { data: { settings: Record<string, unknown> } }).data.settings;
  assert.equal(settings.timeoutMs, 30_000);
  assert.equal(settings.concurrency, 1);
  assert.deepEqual(settings.serverPorts, [25, 587]);
  assert.deepEqual(settings.resolvers, ['203.0.113.1']);
});

test('settings PUT is refused below admin', async () => {
  const result = await call('PUT', '/settings', { role: 'editor', body: { settings: {} } });
  assert.equal(result.status, 403);
});

test('history delete reports 404 for a row nothing matched', async () => {
  // The default mocked `query` returns rowCount: 0, so deleteHistoryEntry
  // should report "not found" rather than a false-positive success.
  const result = await call('DELETE', '/checks/history/42', { role: 'editor' });
  assert.equal(result.status, 404);
  assert.equal((result.body as { error?: string }).error, 'History entry not found');
});

test('history delete rejects a non-numeric id before touching the database', async () => {
  const result = await call('DELETE', '/checks/history/not-a-number', { role: 'editor' });
  assert.equal(result.status, 400);
  assert.equal((result.body as { error?: string }).error, 'Invalid history entry ID');
});

test('rate limiting caps a rate-limited path at 120 requests/minute per admin', async () => {
  // A distinct admin ID so this test's bucket can't be polluted by (or
  // pollute) any other test's calls against the same rate-limited path.
  const adminId = '999999'; // requireAuth requires a numeric, positive admin ID
  let lastStatus = 0;
  for (let i = 0; i < 121; i++) {
    // Empty body fails validation fast (400) well before any real network
    // call, so this loop stays fast and deterministic.
    const result = await call('POST', '/reputation/rbl/run', { role: 'editor', adminId, body: {} });
    lastStatus = result.status;
    if (i < 120) {
      assert.notEqual(result.status, 429, `request ${i + 1}/121 should not be rate-limited yet`);
    }
  }
  assert.equal(lastStatus, 429, 'the 121st request within the window should be rate-limited');
});

test('/checks/run maps user-input validation failures to 400, not 500', async () => {
  // "not-a-domain" passes the handler's own non-empty check but fails the
  // deeper parseDomain() validation inside runToolCheck(), which throws a
  // ValidationError. That must surface as 400 (bad request), not a generic
  // 500 (server fault) — the request itself is what's invalid.
  const result = await call('POST', '/checks/run', {
    role: 'editor',
    body: { toolKind: 'a', targetType: 'domain', targetValue: 'not-a-domain' },
  });
  assert.equal(result.status, 400);
  assert.equal((result.body as { error?: string }).error, 'A valid domain is required');
});

test('/mail-tests/mail-server-test/run maps an unparseable target to 400, not 500', async () => {
  // A target with no valid hostname/domain/IP form fails parseHost() inside
  // runServerTest(), which throws a ValidationError.
  const result = await call('POST', '/mail-tests/mail-server-test/run', {
    role: 'editor',
    body: { target: '###not-a-host###' },
  });
  assert.equal(result.status, 400);
  assert.equal(
    (result.body as { error?: string }).error,
    'A valid hostname, domain, or IP address is required'
  );
});
