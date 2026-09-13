import assert from 'node:assert/strict';
import test from 'node:test';
import { requireAdmin, requireEditor, requireViewer } from './rbac.js';
import type { ModuleAdminContext } from './auth.js';

interface FakeResponse {
  statusCode: number | null;
  body: unknown;
  status(code: number): FakeResponse;
  json(payload: unknown): FakeResponse;
}

function fakeResponse(): FakeResponse {
  const res: FakeResponse = {
    statusCode: null,
    body: undefined,
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

function fakeRequest(moduleAdmin?: ModuleAdminContext): { moduleAdmin?: ModuleAdminContext } {
  return { moduleAdmin };
}

test('requireViewer rejects unauthenticated requests with 401', () => {
  const req = fakeRequest(undefined);
  const res = fakeResponse();
  let called = false;
  requireViewer(req as never, res as never, () => {
    called = true;
  });
  assert.equal(called, false);
  assert.equal(res.statusCode, 401);
});

for (const role of ['viewer', 'editor', 'admin'] as const) {
  test(`requireViewer allows the ${role} role`, () => {
    const req = fakeRequest({ adminId: 1, name: 'A', email: 'a@example.com', role });
    const res = fakeResponse();
    let called = false;
    requireViewer(req as never, res as never, () => {
      called = true;
    });
    assert.equal(called, true);
    assert.equal(res.statusCode, null);
  });
}

test('requireEditor rejects the viewer role with 403', () => {
  const req = fakeRequest({ adminId: 1, name: 'A', email: 'a@example.com', role: 'viewer' });
  const res = fakeResponse();
  let called = false;
  requireEditor(req as never, res as never, () => {
    called = true;
  });
  assert.equal(called, false);
  assert.equal(res.statusCode, 403);
});

for (const role of ['editor', 'admin'] as const) {
  test(`requireEditor allows the ${role} role`, () => {
    const req = fakeRequest({ adminId: 1, name: 'A', email: 'a@example.com', role });
    const res = fakeResponse();
    let called = false;
    requireEditor(req as never, res as never, () => {
      called = true;
    });
    assert.equal(called, true);
    assert.equal(res.statusCode, null);
  });
}

test('requireAdmin rejects the viewer role with 403', () => {
  const req = fakeRequest({ adminId: 1, name: 'A', email: 'a@example.com', role: 'viewer' });
  const res = fakeResponse();
  let called = false;
  requireAdmin(req as never, res as never, () => {
    called = true;
  });
  assert.equal(called, false);
  assert.equal(res.statusCode, 403);
});

test('requireAdmin rejects the editor role with 403', () => {
  const req = fakeRequest({ adminId: 1, name: 'A', email: 'a@example.com', role: 'editor' });
  const res = fakeResponse();
  let called = false;
  requireAdmin(req as never, res as never, () => {
    called = true;
  });
  assert.equal(called, false);
  assert.equal(res.statusCode, 403);
});

test('requireAdmin allows the admin role', () => {
  const req = fakeRequest({ adminId: 1, name: 'A', email: 'a@example.com', role: 'admin' });
  const res = fakeResponse();
  let called = false;
  requireAdmin(req as never, res as never, () => {
    called = true;
  });
  assert.equal(called, true);
  assert.equal(res.statusCode, null);
});

test('requireAdmin rejects unauthenticated requests with 401', () => {
  const req = fakeRequest(undefined);
  const res = fakeResponse();
  let called = false;
  requireAdmin(req as never, res as never, () => {
    called = true;
  });
  assert.equal(called, false);
  assert.equal(res.statusCode, 401);
});
