import type { AuthenticatedSession } from './auth.js';
import {
  createRandomSalt,
  createRecoveryKey,
  decryptText,
  deriveAuthHash,
  deriveEncryptionKey,
  deriveRecoveryAuthHash,
  deriveRecoveryEncryptionKey,
  encryptText,
  importRsaPrivateKey,
} from './crypto/index.js';
import { apiRequest } from './http.js';

export interface RecoveryMaterial {
  recoveryKey: string;
  recoveryAuthHash: string;
  recoveryEncryptedPrivateKey: string;
}

// A new recovery key and a second copy of the private key encrypted with it.
// The key itself is only shown to the user; the server receives the other two values.
export async function createRecoveryMaterial(privateKeyPkcs8: string): Promise<RecoveryMaterial> {
  const recoveryKey = createRecoveryKey();
  const recoveryAuthHash = await deriveRecoveryAuthHash(recoveryKey);
  const recoveryEncryptedPrivateKey = await encryptText(privateKeyPkcs8, await deriveRecoveryEncryptionKey(recoveryKey));
  return { recoveryKey, recoveryAuthHash, recoveryEncryptedPrivateKey };
}

async function decryptWithPassword(session: AuthenticatedSession, masterPassword: string): Promise<string> {
  try {
    return await decryptText(session.encryptedPrivateKey, await deriveEncryptionKey(masterPassword, session.salt));
  } catch {
    throw new Error('Invalid master password');
  }
}

// Forgotten password: the recovery key unlocks the private key, which is then
// re-encrypted under the new password. The used recovery key is replaced by a new one.
export async function recoverAccount(email: string, recoveryKey: string, newMasterPassword: string): Promise<string> {
  const recoveryAuthHash = await deriveRecoveryAuthHash(recoveryKey);
  const { recoveryEncryptedPrivateKey } = await apiRequest<{ recoveryEncryptedPrivateKey: string }>('/api/recovery/key', {
    method: 'POST',
    body: { email, recoveryAuthHash },
  });
  const privateKeyPkcs8 = await decryptText(recoveryEncryptedPrivateKey, await deriveRecoveryEncryptionKey(recoveryKey));
  await importRsaPrivateKey(privateKeyPkcs8);

  const salt = createRandomSalt();
  const authHash = await deriveAuthHash(newMasterPassword, salt);
  const encryptedPrivateKey = await encryptText(privateKeyPkcs8, await deriveEncryptionKey(newMasterPassword, salt));
  const next = await createRecoveryMaterial(privateKeyPkcs8);
  await apiRequest<void>('/api/recovery/reset', {
    method: 'POST',
    body: {
      email,
      recoveryAuthHash,
      salt,
      authHash,
      encryptedPrivateKey,
      newRecoveryAuthHash: next.recoveryAuthHash,
      newRecoveryEncryptedPrivateKey: next.recoveryEncryptedPrivateKey,
    },
  });
  return next.recoveryKey;
}

// Lost or exposed recovery key, or an account created before recovery existed.
export async function regenerateRecoveryKey(session: AuthenticatedSession, masterPassword: string): Promise<string> {
  const privateKeyPkcs8 = await decryptWithPassword(session, masterPassword);
  const authHash = await deriveAuthHash(masterPassword, session.salt);
  const next = await createRecoveryMaterial(privateKeyPkcs8);
  await apiRequest<void>('/api/account/recovery', {
    method: 'PUT',
    token: session.token,
    body: {
      authHash,
      recoveryAuthHash: next.recoveryAuthHash,
      recoveryEncryptedPrivateKey: next.recoveryEncryptedPrivateKey,
    },
  });
  session.hasRecoveryKey = true;
  return next.recoveryKey;
}
