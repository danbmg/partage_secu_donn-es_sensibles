import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AuthenticatedSession } from './auth.js';
import {
  createRandomItemKey,
  createRandomSalt,
  decryptText,
  deriveAuthHash,
  deriveEncryptionKey,
  deriveRecoveryEncryptionKey,
  encryptText,
  generateRsaKeyPair,
  importRsaPrivateKey,
  unwrapItemKey,
  wrapItemKey,
} from './crypto/index.js';
import { rotateAccountKeys } from './keys.js';

afterEach(() => vi.unstubAllGlobals());

describe('account key rotation in the browser', () => {
  it('re-wraps every item key for a new key pair that only the master password unlocks', async () => {
    const password = 'the master password';
    const salt = createRandomSalt();
    const oldPair = await generateRsaKeyPair();
    const session: AuthenticatedSession = {
      token: 'tok',
      userId: 'alice',
      publicKey: oldPair.publicKey,
      privateKey: await importRsaPrivateKey(oldPair.privateKey),
      salt,
      encryptedPrivateKey: await encryptText(oldPair.privateKey, await deriveEncryptionKey(password, salt)),
      hasRecoveryKey: false,
    };
    const itemKeys = [await createRandomItemKey(), await createRandomItemKey()];
    const items = await Promise.all(
      itemKeys.map(async (key, index) => ({ id: `item-${index}`, wrappedKey: await wrapItemKey(key, oldPair.publicKey) })),
    );
    let sent: Record<string, unknown> | undefined;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === '/api/items') return Response.json({ items });
      if (url === '/api/account/rotate-keys') {
        sent = JSON.parse(String(init?.body)) as Record<string, unknown>;
        return new Response(null, { status: 204 });
      }
      throw new Error(`Unexpected API call: ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(rotateAccountKeys(session, 'wrong password')).rejects.toThrow('Invalid master password');
    expect(fetchMock).not.toHaveBeenCalled();

    const result = await rotateAccountKeys(session, password);
    const body = sent as {
      authHash: string;
      publicKey: string;
      encryptedPrivateKey: string;
      recoveryEncryptedPrivateKey: string;
      wrappedKeys: Array<{ itemId: string; wrappedKey: string }>;
    };

    expect(body.authHash).toBe(await deriveAuthHash(password, salt));
    expect(body.publicKey).not.toBe(oldPair.publicKey);
    const newPrivatePkcs8 = await decryptText(body.encryptedPrivateKey, await deriveEncryptionKey(password, salt));
    const newPrivateKey = await importRsaPrivateKey(newPrivatePkcs8);
    expect(body.wrappedKeys.map((entry) => entry.itemId)).toEqual(['item-0', 'item-1']);
    for (const [index, entry] of body.wrappedKeys.entries()) {
      expect(Array.from(await unwrapItemKey(entry.wrappedKey, newPrivateKey))).toEqual(Array.from(itemKeys[index] ?? []));
      await expect(unwrapItemKey(entry.wrappedKey, session.privateKey)).rejects.toThrow();
    }
    expect(await decryptText(body.recoveryEncryptedPrivateKey, await deriveRecoveryEncryptionKey(result.recoveryKey))).toBe(newPrivatePkcs8);
    expect(JSON.stringify(body)).not.toContain(password);
    expect(JSON.stringify(body)).not.toContain(newPrivatePkcs8);

    expect(result.itemCount).toBe(2);
    expect(result.session).toMatchObject({ token: 'tok', publicKey: body.publicKey, encryptedPrivateKey: body.encryptedPrivateKey, hasRecoveryKey: true });
    expect(Array.from(await unwrapItemKey(body.wrappedKeys[0]?.wrappedKey ?? '', result.session.privateKey))).toEqual(Array.from(itemKeys[0] ?? []));
  }, 60_000);
});
