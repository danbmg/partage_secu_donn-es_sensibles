import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import type Database from 'better-sqlite3';

const SESSION_SECONDS = 8 * 60 * 60;
const configuredSecret = process.env.SESSION_SECRET;
if (configuredSecret && Buffer.byteLength(configuredSecret, 'utf8') < 32) {
  throw new Error('SESSION_SECRET must contain at least 32 bytes');
}
const sessionSecret = configuredSecret ? Buffer.from(configuredSecret, 'utf8') : randomBytes(32);

export interface ActiveSession {
  userId: string;
  sessionId: string;
}

function encode(value: object): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function sign(input: string): string {
  return createHmac('sha256', sessionSecret).update(input).digest('base64url');
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

// Checks the signature and the expiry only. A forged token is rejected here,
// before any database lookup.
function readClaims(token: string): { sub: string; sid: string } | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [header, payload, signature] = parts;
  if (!header || !payload || !signature) return null;

  const expected = Buffer.from(sign(`${header}.${payload}`));
  const actual = Buffer.from(signature);
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;

  try {
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as {
      sub?: unknown;
      sid?: unknown;
      exp?: unknown;
    };
    if (typeof claims.sub !== 'string' || typeof claims.sid !== 'string' || typeof claims.exp !== 'number') return null;
    if (claims.exp <= nowSeconds()) return null;
    return { sub: claims.sub, sid: claims.sid };
  } catch {
    return null;
  }
}

export function createSession(database: Database.Database, userId: string): string {
  const now = nowSeconds();
  const sessionId = randomUUID();
  const expiresAt = now + SESSION_SECONDS;
  database.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(now);
  database.prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)').run(sessionId, userId, expiresAt);

  const header = encode({ alg: 'HS256', typ: 'JWT' });
  const payload = encode({ sub: userId, sid: sessionId, iat: now, exp: expiresAt });
  const input = `${header}.${payload}`;
  return `${input}.${sign(input)}`;
}

export function verifySession(database: Database.Database, token: string): ActiveSession | null {
  const claims = readClaims(token);
  if (!claims) return null;
  const row = database
    .prepare('SELECT user_id FROM sessions WHERE id = ? AND expires_at > ?')
    .get(claims.sid, nowSeconds()) as { user_id: string } | undefined;
  if (!row || row.user_id !== claims.sub) return null;
  return { userId: claims.sub, sessionId: claims.sid };
}

export function authenticatedSession(
  database: Database.Database,
  authorization: string | undefined,
): ActiveSession | null {
  if (!authorization?.startsWith('Bearer ')) return null;
  return verifySession(database, authorization.slice('Bearer '.length));
}

export function authenticatedUserId(database: Database.Database, authorization: string | undefined): string | null {
  return authenticatedSession(database, authorization)?.userId ?? null;
}

export function revokeSession(database: Database.Database, sessionId: string): void {
  database.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
}

export function revokeUserSessions(database: Database.Database, userId: string): void {
  database.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
}
