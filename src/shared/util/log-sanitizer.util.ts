const CIRCULAR_REFERENCE = '[Circular]';
const REDACTED = '[REDACTED]';

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function isSensitiveKey(key: string): boolean {
  const normalizedKey = normalizeKey(key);
  return (
    normalizedKey.includes('password') ||
    normalizedKey.includes('token') ||
    normalizedKey.includes('secret') ||
    normalizedKey.includes('authorization') ||
    normalizedKey.includes('cookie') ||
    normalizedKey === 'otp' ||
    normalizedKey.endsWith('otp') ||
    normalizedKey === 'apikey' ||
    normalizedKey.endsWith('apikey')
  );
}

function sanitizeValue(value: unknown, seen: WeakSet<object>): unknown {
  if (value === null || value === undefined) {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeValue(item, seen));
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (typeof value !== 'object') {
    return value;
  }

  if (Buffer.isBuffer(value)) {
    return `[Buffer:${value.length}]`;
  }

  if (seen.has(value)) {
    return CIRCULAR_REFERENCE;
  }

  seen.add(value);

  const source = value as Record<string, unknown>;
  const sanitized: Record<string, unknown> = {};

  for (const [key, nestedValue] of Object.entries(source)) {
    if (isSensitiveKey(key)) {
      sanitized[key] = REDACTED;
      continue;
    }

    sanitized[key] = sanitizeValue(nestedValue, seen);
  }

  return sanitized;
}

export function sanitizeForLogging(value: unknown): unknown {
  return sanitizeValue(value, new WeakSet<object>());
}
