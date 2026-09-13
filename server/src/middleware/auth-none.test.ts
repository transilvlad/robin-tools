import assert from 'node:assert/strict';
import test from 'node:test';

// Module mocking / env vars must be set before config.js (and anything that
// imports it) is loaded, so this runs before the dynamic import below.
process.env.MODULE_PROXY_SECRET = 'test-secret';
process.env.NODE_ENV = 'test';
process.env.DEPLOYMENT_MODE = 'standalone';
process.env.ROBIN_TOOLS_AUTH_MODE = 'none';

const { requireAuth } = await import('./auth.js');

function fakeRequest(): { header: (name: string) => string | undefined; moduleAdmin?: unknown } {
  return { header: () => undefined };
}

test('standalone unauthenticated mode admits every request as the single local admin', () => {
  const req = fakeRequest();
  let called = false;
  requireAuth(req as never, {} as never, () => {
    called = true;
  });
  assert.equal(called, true);
  assert.deepEqual((req as { moduleAdmin?: { role: string; adminId: number } }).moduleAdmin, {
    adminId: 1,
    name: 'Robin Tools',
    email: 'standalone@robin-tools.local',
    role: 'admin',
  });
});
