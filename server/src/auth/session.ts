import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const SESSION_SECONDS = 8 * 60 * 60;
const configuredSecret = process.env.SESSION_SECRET;
if (configuredSecret && Buffer.byteLength(configuredSecret, 'utf8') < 32) {
  throw new Error('SESSION_SECRET must contain at least 32 bytes');
}
const sessionSecret = configuredSecret ? Buffer.from(configuredSecret, 'utf8') : randomBytes(32);

function encode(value: object): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function sign(input: string): string {
  return createHmac('sha256', sessionSecret).update(input).digest('base64url');
}

export function createSession(userId: string): string {
  const now = Math.floor(Date.now() / 1000);
  const header = encode({ alg: 'HS256', typ: 'JWT' });
  const payload = encode({ sub: userId, iat: now, exp: now + SESSION_SECONDS });
  const input = `${header}.${payload}`;
  return `${input}.${sign(input)}`;
}

export function verifySession(token: string): string | null {
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
      exp?: unknown;
    };
    if (typeof claims.sub !== 'string' || typeof claims.exp !== 'number') return null;
    if (claims.exp <= Math.floor(Date.now() / 1000)) return null;
    return claims.sub;
  } catch {
    return null;
  }
}

export function authenticatedUserId(authorization: string | undefined): string | null {
  if (!authorization?.startsWith('Bearer ')) return null;
  return verifySession(authorization.slice('Bearer '.length));
}
