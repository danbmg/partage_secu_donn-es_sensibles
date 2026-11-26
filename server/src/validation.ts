import type { Request } from 'express';

export function objectBody(request: Request): Record<string, unknown> {
  const body: unknown = request.body;
  return typeof body === 'object' && body !== null && !Array.isArray(body) ? (body as Record<string, unknown>) : {};
}

// byteLength < 0 accepts any non-empty value.
export function validBase64(value: unknown, byteLength: number): value is string {
  if (typeof value !== 'string') return false;
  const decoded = Buffer.from(value, 'base64');
  return (byteLength < 0 ? decoded.length > 0 : decoded.length === byteLength) && decoded.toString('base64') === value;
}

export function normalizeEmail(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : null;
}

// A private key encrypted in the browser (AES-GCM envelope as JSON text).
export function validEncryptedKey(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 30_000;
}

// Secrets that only the browser may know. Rejecting them loudly catches a client bug
// that would otherwise leak them into request logs.
export function containsClientSecret(body: Record<string, unknown>): boolean {
  return 'password' in body || 'masterPassword' in body || 'recoveryKey' in body;
}
