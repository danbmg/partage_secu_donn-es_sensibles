import { randomUUID } from 'node:crypto';
import { Router, type Request, type Response } from 'express';
import type Database from 'better-sqlite3';
import { createSession } from '../auth/session.js';
import { hashAuthenticationProof, verifyAuthenticationProof } from '../auth/password-proof.js';

interface AccountRow {
  id: string;
  email: string;
  auth_hash: string;
  public_key: string;
  encrypted_private_key: string;
}

function validBase64(value: unknown, byteLength: number): value is string {
  if (typeof value !== 'string') return false;
  const decoded = Buffer.from(value, 'base64');
  return (byteLength < 0 ? decoded.length > 0 : decoded.length === byteLength) && decoded.toString('base64') === value;
}

function normalizeEmail(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : null;
}

export function authRoutes(database: Database.Database): Router {
  const router = Router();

  router.get('/auth/salt', (request: Request, response: Response) => {
    const email = normalizeEmail(request.query.email);
    if (!email) {
      response.status(400).json({ error: 'Invalid email' });
      return;
    }
    const account = database.prepare('SELECT kdf_salt FROM users WHERE email = ?').get(email) as
      | { kdf_salt: string }
      | undefined;
    if (!account) {
      response.status(404).json({ error: 'Account not found' });
      return;
    }
    response.status(200).json({ salt: account.kdf_salt });
  });

  router.get('/users/:email/public-key', (request: Request, response: Response) => {
    const email = normalizeEmail(request.params.email);
    if (!email) {
      response.status(400).json({ error: 'Invalid email' });
      return;
    }
    const account = database.prepare('SELECT public_key FROM users WHERE email = ?').get(email) as
      | { public_key: string | null }
      | undefined;
    if (!account?.public_key) {
      response.status(404).json({ error: 'Account not found' });
      return;
    }
    response.status(200).json({ publicKey: account.public_key });
  });

  router.post('/register', (request: Request, response: Response) => {
    const email = normalizeEmail(request.body?.email);
    const body = request.body ?? {};
    const { salt, authHash, publicKey, encryptedPrivateKey } = body;
    if (
      !email ||
      !validBase64(salt, 16) ||
      !validBase64(authHash, 32) ||
      !validBase64(publicKey, -1) ||
      Buffer.from(publicKey, 'base64').length < 200 ||
      typeof encryptedPrivateKey !== 'string' ||
      encryptedPrivateKey.length > 30_000
    ) {
      response.status(400).json({ error: 'Invalid registration data' });
      return;
    }
    if ('password' in body || 'masterPassword' in body) {
      response.status(400).json({ error: 'Passwords must never be sent to the server' });
      return;
    }

    const id = randomUUID();
    try {
      database
        .prepare(
          'INSERT INTO users (id, email, kdf_salt, auth_hash, public_key, encrypted_private_key) VALUES (?, ?, ?, ?, ?, ?)',
        )
        .run(id, email, salt, hashAuthenticationProof(authHash), publicKey, encryptedPrivateKey);
    } catch (error) {
      if (error instanceof Error && error.message.includes('UNIQUE constraint failed')) {
        response.status(409).json({ error: 'Account already exists' });
        return;
      }
      throw error;
    }

    response.status(201).json({ userId: id });
  });

  router.post('/login', (request: Request, response: Response) => {
    const email = normalizeEmail(request.body?.email);
    const body = request.body ?? {};
    const { authHash } = body;
    if (!email || !validBase64(authHash, 32)) {
      response.status(400).json({ error: 'Invalid login data' });
      return;
    }
    if ('password' in body || 'masterPassword' in body) {
      response.status(400).json({ error: 'Passwords must never be sent to the server' });
      return;
    }

    const account = database
      .prepare('SELECT id, email, auth_hash, public_key, encrypted_private_key FROM users WHERE email = ?')
      .get(email) as AccountRow | undefined;
    if (!account || !verifyAuthenticationProof(authHash, account.auth_hash)) {
      response.status(401).json({ error: 'Invalid email or authentication proof' });
      return;
    }

    database.prepare("INSERT INTO audit_log (user_id, action) VALUES (?, 'login')").run(account.id);
    response.status(200).json({
      token: createSession(account.id),
      userId: account.id,
      publicKey: account.public_key,
      encryptedPrivateKey: account.encrypted_private_key,
    });
  });

  return router;
}
