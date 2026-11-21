import { beforeEach, describe, expect, it, vi } from 'vitest';
import { csrfUrlFor, moduleApiFetch } from './moduleApi';

describe('csrfUrlFor', () => {
  it('uses the API root of the module base path', () => {
    expect(csrfUrlFor('/api/modules/robin-tools')).toBe('/api/auth/csrf');
    expect(csrfUrlFor('/admin/api/modules/robin-tools')).toBe('/admin/api/auth/csrf');
    expect(csrfUrlFor('/api')).toBe('/api/auth/csrf');
    expect(csrfUrlFor('https://admin.example.com/admin/api/modules/robin-tools')).toBe(
      'https://admin.example.com/admin/api/auth/csrf'
    );
  });
});

describe('moduleApiFetch', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('rejects successful non-JSON responses', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('<html>proxy error</html>', {
        status: 200,
        headers: { 'content-type': 'text/html' },
      })
    );

    await expect(moduleApiFetch('/api/modules/robin-tools', '/history')).rejects.toThrow(
      'invalid response'
    );
  });

  it('fetches CSRF state and forwards only the returned token for writes', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            success: true,
            data: { csrfToken: 'csrf-test' },
          }),
          {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }
        )
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            success: true,
            data: { id: 1 },
          }),
          {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }
        )
      );

    await expect(
      moduleApiFetch<{ id: number }>('/api/modules/robin-tools', '/history', {
        method: 'POST',
        body: '{}',
      })
    ).resolves.toEqual({ id: 1 });

    const headers = fetchMock.mock.calls[1][1]?.headers as Headers;
    expect(headers.get('x-csrf-token')).toBe('csrf-test');
    expect(fetchMock.mock.calls[1][0]).toBe('/api/modules/robin-tools/history');
  });

  it('fetches CSRF state from the host API root when served under a path prefix', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ success: true, data: { csrfToken: 'csrf-prefixed' } }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ success: true, data: { id: 2 } }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      );

    await expect(
      moduleApiFetch<{ id: number }>('/admin/api/modules/robin-tools', '/history', {
        method: 'POST',
        body: '{}',
      })
    ).resolves.toEqual({ id: 2 });

    expect(fetchMock.mock.calls[0][0]).toBe('/admin/api/auth/csrf');
    expect(fetchMock.mock.calls[1][0]).toBe('/admin/api/modules/robin-tools/history');
    const headers = fetchMock.mock.calls[1][1]?.headers as Headers;
    expect(headers.get('x-csrf-token')).toBe('csrf-prefixed');
  });

  it('reports malformed JSON without leaking response contents', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('{secret', {
        status: 502,
        headers: { 'content-type': 'application/json' },
      })
    );

    await expect(moduleApiFetch('/api/modules/robin-tools', '/history')).rejects.toThrow(
      'malformed JSON'
    );
  });

  it('does not start an already-cancelled write', async () => {
    const controller = new AbortController();
    controller.abort();
    const fetchMock = vi.spyOn(globalThis, 'fetch');

    await expect(
      moduleApiFetch('/api/modules/robin-tools', '/history', {
        method: 'POST',
        body: '{}',
        signal: controller.signal,
      })
    ).rejects.toThrow('cancelled');

    expect(fetchMock).not.toHaveBeenCalled();
  });
});
