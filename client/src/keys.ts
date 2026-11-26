import type { AuthenticatedSession } from './auth.js';
import {
  deriveAuthHash,
  deriveEncryptionKey,
  encryptText,
  generateRsaKeyPair,
  importRsaPrivateKey,
  unwrapItemKey,
  wrapItemKey,
} from './crypto/index.js';
import { apiRequest } from './http.js';
import { createRecoveryMaterial, decryptPrivateKeyWithPassword } from './recovery.js';

interface HeldItem {
  id: string;
  wrappedKey: string;
}

export interface KeyRotation {
  session: AuthenticatedSession;
  recoveryKey: string;
  itemCount: number;
}

// Replaces the account key pair. Item contents are not touched: only the small item keys
// are unwrapped with the old private key and wrapped again with the new public key.
export async function rotateAccountKeys(session: AuthenticatedSession, masterPassword: string): Promise<KeyRotation> {
  await decryptPrivateKeyWithPassword(session, masterPassword);
  const authHash = await deriveAuthHash(masterPassword, session.salt);

  const { items } = await apiRequest<{ items: HeldItem[] }>('/api/items', { token: session.token });
  const pair = await generateRsaKeyPair();
  const wrappedKeys = await Promise.all(
    items.map(async (item) => ({
      itemId: item.id,
      wrappedKey: await wrapItemKey(await unwrapItemKey(item.wrappedKey, session.privateKey), pair.publicKey),
    })),
  );
  const encryptedPrivateKey = await encryptText(pair.privateKey, await deriveEncryptionKey(masterPassword, session.salt));
  // The old recovery key would restore the old private key, which no longer opens anything.
  const recovery = await createRecoveryMaterial(pair.privateKey);

  await apiRequest<void>('/api/account/rotate-keys', {
    method: 'POST',
    token: session.token,
    body: {
      authHash,
      publicKey: pair.publicKey,
      encryptedPrivateKey,
      recoveryAuthHash: recovery.recoveryAuthHash,
      recoveryEncryptedPrivateKey: recovery.recoveryEncryptedPrivateKey,
      wrappedKeys,
    },
  });

  return {
    session: {
      ...session,
      publicKey: pair.publicKey,
      privateKey: await importRsaPrivateKey(pair.privateKey),
      encryptedPrivateKey,
      hasRecoveryKey: true,
    },
    recoveryKey: recovery.recoveryKey,
    itemCount: items.length,
  };
}
