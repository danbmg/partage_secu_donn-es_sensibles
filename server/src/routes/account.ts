import { Router, type Request, type Response } from 'express';
import type Database from 'better-sqlite3';
import { recordAudit } from '../audit.js';
import { hashAuthenticationProof, verifyAuthenticationProof } from '../auth/password-proof.js';
import { requestUserId } from '../auth/require-session.js';
import { revokeUserSessions } from '../auth/session.js';
import { containsClientSecret, normalizeEmail, objectBody, validBase64, validEncryptedKey } from '../validation.js';

interface RecoveryRow {
  id: string;
  recovery_auth_hash: string | null;
  recovery_encrypted_private_key: string | null;
}

export function accountRoutes(database: Database.Database): Router {
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
    const account = findRecoverableAccount(email, recoveryAuthHash);
    if (!account) {
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
    const account = findRecoverableAccount(email, recoveryAuthHash);
    if (!account) {
      response.status(401).json({ error: 'Invalid email or recovery key' });
      return;
    }

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
    const account = database.prepare('SELECT auth_hash FROM users WHERE id = ?').get(userId) as
      | { auth_hash: string }
      | undefined;
    // 403, not 401: the session is valid, only the password proof is wrong.
    if (!account || !verifyAuthenticationProof(authHash, account.auth_hash)) {
      response.status(403).json({ error: 'Invalid master password' });
      return;
    }

    const update = database.transaction(() => {
      database
        .prepare('UPDATE users SET recovery_auth_hash = ?, recovery_encrypted_private_key = ? WHERE id = ?')
        .run(hashAuthenticationProof(recoveryAuthHash), recoveryEncryptedPrivateKey, userId);
      recordAudit(database, { userId, action: 'recovery-update' });
    });
    update();
    response.status(204).end();
  });

  return router;
}
