import { randomUUID } from 'node:crypto';
import { Router, type Request, type Response } from 'express';
import type Database from 'better-sqlite3';
import { createSession } from '../auth/session.js';
import { hashAuthenticationProof, verifyAuthenticationProof } from '../auth/password-proof.js';

interface AccountRow {
  id: string;
  email: string;
  auth_hash: string;
}

function validBase64(value: unknown, byteLength: number): value is string {
  if (typeof value !== 'string') return false;
  const decoded = Buffer.from(value, 'base64');
  return decoded.length === byteLength && decoded.toString('base64') === value;
}

function normalizeEmail(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : null;
}

export function authRoutes(database: Database.Database): Router {
  const router = Router();

  router.post('/register', (request: Request, response: Response) => {
    const email = normalizeEmail(request.body?.email);
    const body = request.body ?? {};
    const { salt, authHash } = body;
    if (!email || !validBase64(salt, 16) || !validBase64(authHash, 32)) {
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
        .prepare('INSERT INTO users (id, email, kdf_salt, auth_hash) VALUES (?, ?, ?, ?)')
        .run(id, email, salt, hashAuthenticationProof(authHash));
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
      .prepare('SELECT id, email, auth_hash FROM users WHERE email = ?')
      .get(email) as AccountRow | undefined;
    if (!account || !verifyAuthenticationProof(authHash, account.auth_hash)) {
      response.status(401).json({ error: 'Invalid email or authentication proof' });
      return;
    }

    database.prepare("INSERT INTO audit_log (user_id, action) VALUES (?, 'login')").run(account.id);
    response.status(200).json({ token: createSession(account.id), userId: account.id });
  });

  return router;
}
