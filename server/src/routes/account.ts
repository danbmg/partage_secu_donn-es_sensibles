import { Router, type Request, type Response } from 'express';
import type Database from 'better-sqlite3';
import { recordAudit } from '../audit.js';
import { hashAuthenticationProof, verifyAuthenticationProof } from '../auth/password-proof.js';
import { rejectIfLimited, type FailureLimiter } from '../auth/rate-limit.js';
import { requestSession, requestUserId } from '../auth/require-session.js';
import { revokeUserSessions } from '../auth/session.js';
import {
  containsClientSecret,
  normalizeEmail,
  objectBody,
  validBase64,
  validEncryptedKey,
  validWrappedKey,
} from '../validation.js';

interface ItemKeyEntry {
  itemId: string;
  wrappedKey: string;
}

function validItemKeyList(value: unknown): value is ItemKeyEntry[] {
  if (!Array.isArray(value) || value.length > 5_000) return false;
  const seen = new Set<string>();
  for (const entry of value as unknown[]) {
    if (typeof entry !== 'object' || entry === null) return false;
    const { itemId, wrappedKey } = entry as Record<string, unknown>;
    if (typeof itemId !== 'string' || seen.has(itemId) || !validWrappedKey(wrappedKey)) return false;
    seen.add(itemId);
  }
  return true;
}

interface RecoveryRow {
  id: string;
  recovery_auth_hash: string | null;
  recovery_encrypted_private_key: string | null;
}

export function accountRoutes(database: Database.Database, limiter: FailureLimiter): Router {
  const router = Router();

  // Same answer for an unknown email, an account without recovery key and a wrong proof.
  function findRecoverableAccount(email: string, recoveryAuthHash: string): RecoveryRow | null {
    const account = database
      .prepare('SELECT id, recovery_auth_hash, recovery_encrypted_private_key FROM users WHERE email = ?')
      .get(email) as RecoveryRow | undefined;
    if (!account?.recovery_auth_hash || !account.recovery_encrypted_private_key) return null;
    return verifyAuthenticationProof(recoveryAuthHash, account.recovery_auth_hash) ? account : null;
  }

  // Step 1 of a forgotten-password reset: prove the recovery key, receive the private key
  // encrypted with it. The browser decrypts it; the server never could.
  router.post('/recovery/key', (request: Request, response: Response) => {
    const body = objectBody(request);
    const email = normalizeEmail(body.email);
    const { recoveryAuthHash } = body;
    if (containsClientSecret(body)) {
      response.status(400).json({ error: 'Recovery keys must never be sent to the server' });
      return;
    }
    if (!email || !validBase64(recoveryAuthHash, 32)) {
      response.status(400).json({ error: 'Invalid recovery data' });
      return;
    }
    const attemptKey = `recovery:${request.ip}|${email}`;
    if (rejectIfLimited(limiter, attemptKey, response)) return;
    const account = findRecoverableAccount(email, recoveryAuthHash);
    if (!account) {
      limiter.recordFailure(attemptKey);
      response.status(401).json({ error: 'Invalid email or recovery key' });
      return;
    }
    response.status(200).json({ recoveryEncryptedPrivateKey: account.recovery_encrypted_private_key });
  });

  // Step 2: replace the password material and the recovery material in one go,
  // then close every open session of the account.
  router.post('/recovery/reset', (request: Request, response: Response) => {
    const body = objectBody(request);
    const email = normalizeEmail(body.email);
    const { recoveryAuthHash, salt, authHash, encryptedPrivateKey, newRecoveryAuthHash, newRecoveryEncryptedPrivateKey } = body;
    if (containsClientSecret(body)) {
      response.status(400).json({ error: 'Recovery keys must never be sent to the server' });
      return;
    }
    if (
      !email ||
      !validBase64(recoveryAuthHash, 32) ||
      !validBase64(salt, 16) ||
      !validBase64(authHash, 32) ||
      !validEncryptedKey(encryptedPrivateKey) ||
      !validBase64(newRecoveryAuthHash, 32) ||
      !validEncryptedKey(newRecoveryEncryptedPrivateKey)
    ) {
      response.status(400).json({ error: 'Invalid recovery data' });
      return;
    }
    const attemptKey = `recovery:${request.ip}|${email}`;
    if (rejectIfLimited(limiter, attemptKey, response)) return;
    const account = findRecoverableAccount(email, recoveryAuthHash);
    if (!account) {
      limiter.recordFailure(attemptKey);
      response.status(401).json({ error: 'Invalid email or recovery key' });
      return;
    }
    limiter.reset(attemptKey);

    const reset = database.transaction(() => {
      database
        .prepare(
          `UPDATE users SET kdf_salt = ?, auth_hash = ?, encrypted_private_key = ?,
                            recovery_auth_hash = ?, recovery_encrypted_private_key = ?
           WHERE id = ?`,
        )
        .run(
          salt,
          hashAuthenticationProof(authHash),
          encryptedPrivateKey,
          hashAuthenticationProof(newRecoveryAuthHash),
          newRecoveryEncryptedPrivateKey,
          account.id,
        );
      revokeUserSessions(database, account.id);
      recordAudit(database, { userId: account.id, action: 'recover' });
    });
    reset();
    response.status(204).end();
  });

  // Replace the recovery key while logged in. The session alone is not enough:
  // the master password proof is required too, so a stolen token cannot plant
  // its own recovery key and take the account over.
  router.put('/account/recovery', (request: Request, response: Response) => {
    const userId = requestUserId(database, request);
    if (!userId) {
      response.status(401).json({ error: 'Authentication required' });
      return;
    }
    const body = objectBody(request);
    const { authHash, recoveryAuthHash, recoveryEncryptedPrivateKey } = body;
    if (containsClientSecret(body)) {
      response.status(400).json({ error: 'Recovery keys must never be sent to the server' });
      return;
    }
    if (!validBase64(authHash, 32) || !validBase64(recoveryAuthHash, 32) || !validEncryptedKey(recoveryEncryptedPrivateKey)) {
      response.status(400).json({ error: 'Invalid recovery data' });
      return;
    }
    // A stolen session must not become a way to brute-force the master password.
    const attemptKey = `password:${userId}`;
    if (rejectIfLimited(limiter, attemptKey, response)) return;
    const account = database.prepare('SELECT auth_hash FROM users WHERE id = ?').get(userId) as
      | { auth_hash: string }
      | undefined;
    // 403, not 401: the session is valid, only the password proof is wrong.
    if (!account || !verifyAuthenticationProof(authHash, account.auth_hash)) {
      limiter.recordFailure(attemptKey);
      response.status(403).json({ error: 'Invalid master password' });
      return;
    }
    limiter.reset(attemptKey);

    const update = database.transaction(() => {
      database
        .prepare('UPDATE users SET recovery_auth_hash = ?, recovery_encrypted_private_key = ? WHERE id = ?')
        .run(hashAuthenticationProof(recoveryAuthHash), recoveryEncryptedPrivateKey, userId);
      recordAudit(database, { userId, action: 'recovery-update' });
    });
    update();
    response.status(204).end();
  });

  // Key pair rotation. The browser sends a new public key, the new private key encrypted
  // under the master password, every item key it holds re-wrapped for the new public key,
  // and new recovery material (the old one protects a private key that is now useless).
  router.post('/account/rotate-keys', (request: Request, response: Response) => {
    const session = requestSession(database, request);
    if (!session) {
      response.status(401).json({ error: 'Authentication required' });
      return;
    }
    const body = objectBody(request);
    const { authHash, publicKey, encryptedPrivateKey, recoveryAuthHash, recoveryEncryptedPrivateKey, wrappedKeys } = body;
    if (containsClientSecret(body)) {
      response.status(400).json({ error: 'Passwords must never be sent to the server' });
      return;
    }
    if (
      !validBase64(authHash, 32) ||
      !validBase64(publicKey, -1) ||
      Buffer.from(publicKey, 'base64').length < 200 ||
      !validEncryptedKey(encryptedPrivateKey) ||
      !validBase64(recoveryAuthHash, 32) ||
      !validEncryptedKey(recoveryEncryptedPrivateKey) ||
      !validItemKeyList(wrappedKeys)
    ) {
      response.status(400).json({ error: 'Invalid key rotation data' });
      return;
    }
    const { userId, sessionId } = session;
    const attemptKey = `password:${userId}`;
    if (rejectIfLimited(limiter, attemptKey, response)) return;
    const account = database.prepare('SELECT auth_hash FROM users WHERE id = ?').get(userId) as
      | { auth_hash: string }
      | undefined;
    if (!account || !verifyAuthenticationProof(authHash, account.auth_hash)) {
      limiter.recordFailure(attemptKey);
      response.status(403).json({ error: 'Invalid master password' });
      return;
    }
    limiter.reset(attemptKey);

    const rotate = database.transaction(() => {
      // Every item key the user holds must come back re-wrapped, or that item
      // would become unreadable: the old private key is about to disappear.
      const held = new Set(
        (database.prepare('SELECT item_id FROM item_keys WHERE user_id = ?').all(userId) as Array<{ item_id: string }>).map(
          (row) => row.item_id,
        ),
      );
      if (held.size !== wrappedKeys.length || wrappedKeys.some((entry) => !held.has(entry.itemId))) return false;

      database
        .prepare(
          `UPDATE users SET public_key = ?, encrypted_private_key = ?,
                            recovery_auth_hash = ?, recovery_encrypted_private_key = ?
           WHERE id = ?`,
        )
        .run(publicKey, encryptedPrivateKey, hashAuthenticationProof(recoveryAuthHash), recoveryEncryptedPrivateKey, userId);
      const updateKey = database.prepare('UPDATE item_keys SET wrapped_key = ? WHERE item_id = ? AND user_id = ?');
      for (const entry of wrappedKeys) updateKey.run(entry.wrappedKey, entry.itemId, userId);
      // Other devices still hold the old private key in memory and could no longer
      // decrypt anything: close them so they log in again and fetch the new one.
      revokeUserSessions(database, userId, sessionId);
      recordAudit(database, { userId, action: 'rotate-keys' });
      return true;
    });
    if (!rotate()) {
      response.status(409).json({ error: 'Your item list changed, reload and try again' });
      return;
    }
    response.status(204).end();
  });

  return router;
}
