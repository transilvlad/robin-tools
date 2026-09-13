type Meta = Record<string, unknown> | undefined;

const SENSITIVE_KEY = /password|secret|token|authorization|cookie/i;

function sanitize(value: unknown, key = ''): unknown {
  if (SENSITIVE_KEY.test(key)) {
    return '[redacted]';
  }
  if (process.env.NODE_ENV === 'production' && (key === 'error' || key === 'stack')) {
    return '[redacted]';
  }
  if (typeof value === 'string') {
    return value.replace(/[\r\n\t]+/g, ' ').slice(0, 1000);
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitize(item));
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([childKey, childValue]) => [
        childKey,
        sanitize(childValue, childKey),
      ])
    );
  }
  return value;
}

function write(level: string, message: string, meta?: Meta) {
  const safeMeta = meta ? (sanitize(meta) as Record<string, unknown>) : undefined;
  const payload =
    safeMeta && Object.keys(safeMeta).length > 0 ? ` ${JSON.stringify(safeMeta)}` : '';
  console.log(`${new Date().toISOString()} [${level}] ${sanitize(message)}${payload}`);
}

export const logger = {
  debug(message: string, meta?: Meta) {
    if ((process.env.LOG_LEVEL || 'info') === 'debug') {
      write('debug', message, meta);
    }
  },
  info(message: string, meta?: Meta) {
    write('info', message, meta);
  },
  warn(message: string, meta?: Meta) {
    write('warn', message, meta);
  },
  error(message: string, meta?: Meta) {
    write('error', message, meta);
  },
};
