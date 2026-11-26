import type { Response } from 'express';

// Counts failed attempts per key (e.g. "login:<ip>|<email>") over a sliding window.
// The proofs are already slow to compute offline (PBKDF2 + scrypt); this caps how
// many guesses an attacker gets online against one account.
export class FailureLimiter {
  private readonly failures = new Map<string, number[]>();
  private readonly maxFailures: number;
  private readonly windowMs: number;
  private readonly now: () => number;

  constructor(maxFailures: number, windowMs: number, now: () => number = Date.now) {
    this.maxFailures = maxFailures;
    this.windowMs = windowMs;
    this.now = now;
  }

  // Seconds to wait before the next attempt, 0 when an attempt is allowed.
  retryAfter(key: string): number {
    const recent = this.recent(key);
    if (recent.length < this.maxFailures) return 0;
    return Math.max(1, Math.ceil(((recent[0] as number) + this.windowMs - this.now()) / 1000));
  }

  recordFailure(key: string): void {
    const recent = this.recent(key);
    recent.push(this.now());
    this.failures.set(key, recent);
    if (this.failures.size > 10_000) this.forgetExpired();
  }

  reset(key: string): void {
    this.failures.delete(key);
  }

  private recent(key: string): number[] {
    const cutoff = this.now() - this.windowMs;
    return (this.failures.get(key) ?? []).filter((time) => time > cutoff);
  }

  private forgetExpired(): void {
    for (const key of [...this.failures.keys()]) {
      if (this.recent(key).length === 0) this.failures.delete(key);
    }
  }
}

export const MAX_FAILED_ATTEMPTS = 5;
export const FAILURE_WINDOW_MS = 15 * 60 * 1000;

export function createFailureLimiter(): FailureLimiter {
  return new FailureLimiter(MAX_FAILED_ATTEMPTS, FAILURE_WINDOW_MS);
}

// Answers 429 and returns true when the key is over its budget.
export function rejectIfLimited(limiter: FailureLimiter, key: string, response: Response): boolean {
  const wait = limiter.retryAfter(key);
  if (wait === 0) return false;
  response.setHeader('Retry-After', String(wait));
  response.status(429).json({ error: 'Too many failed attempts, try again later' });
  return true;
}
