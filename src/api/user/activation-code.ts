import { randomInt } from 'node:crypto';

export const ACTIVATION_MODE = 1;
export const ACTIVATION_LIFETIME_MS = 24 * 60 * 60 * 1000;
export const MAX_CODE_ATTEMPTS = 3;
const MAX_DAILY_SENDS = 5;
const MAX_DAILY_FAILURES = 10;
const RESEND_INTERVAL_MS = 60 * 1000;

export function recentActivationEvents(events: Date[], now: Date): Date[] {
  return events.filter(
    (time) => time.getTime() > now.getTime() - ACTIVATION_LIFETIME_MS,
  );
}

// Both arrays are chronological and bounded by their respective limits.
export function nextActivationSend(
  sends: Date[],
  failures: Date[],
  now: Date,
): Date | null {
  const recent = recentActivationEvents(sends, now);
  const next = Math.max(
    recent.length
      ? recent[recent.length - 1].getTime() + RESEND_INTERVAL_MS
      : 0,
    recent.length >= MAX_DAILY_SENDS
      ? recent[0].getTime() + ACTIVATION_LIFETIME_MS
      : 0,
    activationAttemptRetry(failures, now)?.getTime() || 0,
  );
  return next > now.getTime() ? new Date(next) : null;
}

export function activationAttemptRetry(
  failures: Date[],
  now: Date,
): Date | null {
  const recent = recentActivationEvents(failures, now);
  return recent.length >= MAX_DAILY_FAILURES
    ? new Date(recent[0].getTime() + ACTIVATION_LIFETIME_MS)
    : null;
}

export function newActivationCode(previous?: string): string {
  let code: string;
  do {
    code = randomInt(1000000).toString().padStart(6, '0');
  } while (code === previous);
  return code;
}
