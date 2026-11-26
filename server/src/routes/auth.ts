import { randomUUID } from 'node:crypto';
import { Router, type Request, type Response } from 'express';
import type Database from 'better-sqlite3';
import { recordAudit } from '../audit.js';
import { requestSession } from '../auth/require-session.js';
import { createSession, revokeSession } from '../auth/session.js';
import { hashAuthenticationProof, verifyAuthenticationProof } from '../auth/password-proof.js';
import { rejectIfLimited, type FailureLimiter } from '../auth/rate-limit.js';
import { containsClientSecret, normalizeEmail, objectBody, validBase64, validEncryptedKey } from '../validation.js';

interface AccountRow {
  id: string;
  email: string;
  auth_hash: string;
  public_key: string;
  encrypted_private_key: string;
  recovery_auth_hash: string | null;
}

export function authRoutes(database: Database.Database, limiter: FailureLimiter): Router {
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
    const body = objectBody(request);
    const email = normalizeEmail(body.email);
    const { salt, authHash, publicKey, encryptedPrivateKey, recoveryAuthHash, recoveryEncryptedPrivateKey } = body;
    if (
      !email ||
      !validBase64(salt, 16) ||
      !validBase64(authHash, 32) ||
      !validBase64(publicKey, -1) ||
      Buffer.from(publicKey, 'base64').length < 200 ||
      !validEncryptedKey(encryptedPrivateKey) ||
      !validBase64(recoveryAuthHash, 32) ||
      !validEncryptedKey(recoveryEncryptedPrivateKey)
    ) {
      response.status(400).json({ error: 'Invalid registration data' });
      return;
    }
    if (containsClientSecret(body)) {
      response.status(400).json({ error: 'Passwords must never be sent to the server' });
      return;
    }

    const id = randomUUID();
    try {
      database
        .prepare(
          `INSERT INTO users (id, email, kdf_salt, auth_hash, public_key, encrypted_private_key,
                              recovery_auth_hash, recovery_encrypted_private_key)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          id,
          email,
          salt,
          hashAuthenticationProof(authHash),
          publicKey,
          encryptedPrivateKey,
          hashAuthenticationProof(recoveryAuthHash),
          recoveryEncryptedPrivateKey,
        );
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
    const body = objectBody(request);
    const email = normalizeEmail(body.email);
    const { authHash } = body;
    if (!email || !validBase64(authHash, 32)) {
      response.status(400).json({ error: 'Invalid login data' });
      return;
    }
    if (containsClientSecret(body)) {
      response.status(400).json({ error: 'Passwords must never be sent to the server' });
      return;
    }
    const attemptKey = `login:${request.ip}|${email}`;
    if (rejectIfLimited(limiter, attemptKey, response)) return;

    const account = database
      .prepare(
        'SELECT id, email, auth_hash, public_key, encrypted_private_key, recovery_auth_hash FROM users WHERE email = ?',
      )
      .get(email) as AccountRow | undefined;
    if (!account || !verifyAuthenticationProof(authHash, account.auth_hash)) {
      limiter.recordFailure(attemptKey);
      response.status(401).json({ error: 'Invalid email or authentication proof' });
      return;
    }
    limiter.reset(attemptKey);

    recordAudit(database, { userId: account.id, action: 'login' });
    response.status(200).json({
      token: createSession(database, account.id),
      userId: account.id,
      publicKey: account.public_key,
      encryptedPrivateKey: account.encrypted_private_key,
      hasRecoveryKey: account.recovery_auth_hash !== null,
    });
  });

  router.post('/logout', (request: Request, response: Response) => {
    const session = requestSession(database, request);
    if (!session) {
      response.status(401).json({ error: 'Authentication required' });
      return;
    }
    revokeSession(database, session.sessionId);
    recordAudit(database, { userId: session.userId, action: 'logout' });
    response.status(204).end();
  });

  return router;
}
