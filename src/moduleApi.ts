interface ApiEnvelope<T> {
  success: boolean;
  data?: T;
  error?: string;
}

let csrfToken: string | null = null;
const API_TIMEOUT_MS = 15_000;

async function fetchWithTimeout(url: string, init: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const timer = globalThis.setTimeout(() => controller.abort(), API_TIMEOUT_MS);
  const abort = () => controller.abort();
  if (init.signal?.aborted) {
    controller.abort();
  } else {
    init.signal?.addEventListener('abort', abort, { once: true });
  }

  try {
    if (controller.signal.aborted) {
      throw new Error('Request cancelled');
    }
    return await fetch(url, { ...init, signal: controller.signal });
  } catch {
    if (controller.signal.aborted) {
      throw new Error(init.signal?.aborted ? 'Request cancelled' : 'Request timed out');
    }
    throw new Error('Unable to reach Robin Tools');
  } finally {
    globalThis.clearTimeout(timer);
    init.signal?.removeEventListener('abort', abort);
  }
}

async function readEnvelope<T>(response: Response): Promise<ApiEnvelope<T>> {
  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.toLowerCase().includes('application/json')) {
    throw new Error(
      response.ok
        ? 'Robin Tools returned an invalid response'
        : `Request failed: ${response.status}`
    );
  }

  try {
    return (await response.json()) as ApiEnvelope<T>;
  } catch {
    throw new Error('Robin Tools returned malformed JSON');
  }
}

async function ensureCsrfToken(signal?: AbortSignal | null): Promise<string | null> {
  if (csrfToken) {
    return csrfToken;
  }

  const response = await fetchWithTimeout('/api/auth/csrf', {
    credentials: 'include',
    signal: signal ?? undefined,
  });
  const payload = await readEnvelope<{ csrfToken?: string }>(response);
  if (!response.ok || !payload.success) {
    throw new Error(payload.error || `Unable to prepare request: ${response.status}`);
  }
  csrfToken = payload.data?.csrfToken ?? null;
  return csrfToken;
}

export async function moduleApiFetch<T>(
  basePath: string,
  path: string,
  init?: RequestInit,
  options?: { csrf?: boolean }
): Promise<T> {
  const method = (init?.method ?? 'GET').toUpperCase();
  const unsafe = !['GET', 'HEAD', 'OPTIONS'].includes(method);
  const useCsrf = options?.csrf !== false;
  const headers = new Headers(init?.headers ?? {});

  if (!headers.has('Content-Type') && init?.body) {
    headers.set('Content-Type', 'application/json');
  }

  if (unsafe && useCsrf) {
    const token = await ensureCsrfToken(init?.signal);
    if (token) {
      headers.set('X-CSRF-Token', token);
    }
    if (init?.signal?.aborted) {
      throw new Error('Request cancelled');
    }
  }

  const response = await fetchWithTimeout(`${basePath}${path}`, {
    credentials: 'include',
    ...init,
    method,
    headers,
  });

  const body = await readEnvelope<T>(response);
  if (!response.ok || !body.success || body.data === undefined) {
    throw new Error(body.error || `Request failed: ${response.status}`);
  }

  return body.data;
}
