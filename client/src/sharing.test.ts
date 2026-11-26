import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AuthenticatedSession } from './auth.js';
import {
  createRandomItemKey,
  decryptText,
  encryptText,
  generateRsaKeyPair,
  importAesKey,
  importRsaPrivateKey,
  unwrapItemKey,
  wrapItemKey,
} from './crypto/index.js';
import { revokeVaultItemAccess, shareVaultItem } from './sharing.js';

afterEach(() => vi.unstubAllGlobals());

describe('client-side item sharing', () => {
  it('wraps the item key for the recipient and sends no secret data to the server', async () => {
    const ownerKeys = await generateRsaKeyPair();
    const recipientKeys = await generateRsaKeyPair();
    const session: AuthenticatedSession = {
      token: 'owner-token',
      userId: 'owner-1',
      publicKey: ownerKeys.publicKey,
      privateKey: await importRsaPrivateKey(ownerKeys.privateKey),
      salt: '',
      encryptedPrivateKey: '',
      hasRecoveryKey: true,
    };
    const secretText = JSON.stringify({ name: 'Bank credentials', password: 'never sent as plaintext' });
    const rawItemKey = await createRandomItemKey();
    const aesKey = await importAesKey(rawItemKey);
    const ciphertext = await encryptText(secretText, aesKey);
    const ownerWrappedKey = await wrapItemKey(rawItemKey, ownerKeys.publicKey);
    let sharePayload: Record<string, string> | undefined;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === '/api/users/bob%40example.com/public-key') return Response.json({ publicKey: recipientKeys.publicKey });
        if (url === '/api/items/item-1') return Response.json({ id: 'item-1', ciphertext, wrappedKey: ownerWrappedKey });
        if (url === '/api/items/item-1/shares' && init?.method === 'POST') {
          sharePayload = JSON.parse(String(init.body)) as Record<string, string>;
          return Response.json({ sharedWithUserId: 'recipient-1' }, { status: 201 });
        }
        throw new Error(`Unexpected API call: ${url}`);
      }),
    );

    await shareVaultItem('item-1', 'bob@example.com', session);
    expect(sharePayload?.email).toBe('bob@example.com');
    expect(sharePayload?.recipientPublicKey).toBe(recipientKeys.publicKey);
    expect(JSON.stringify(sharePayload)).not.toContain('never sent as plaintext');
    const recipientPrivateKey = await importRsaPrivateKey(recipientKeys.privateKey);
    const recipientRawKey = await unwrapItemKey(sharePayload?.wrappedKey ?? '', recipientPrivateKey);
    const recipientAesKey = await importAesKey(recipientRawKey);
    expect(await decryptText(ciphertext, recipientAesKey)).toBe(secretText);
  }, 15_000);

  it('re-encrypts the item under a new key that only the remaining holders can unwrap', async () => {
    const [owner, bob, carol] = await Promise.all([generateRsaKeyPair(), generateRsaKeyPair(), generateRsaKeyPair()]);
    const session: AuthenticatedSession = {
      token: 'owner-token',
      userId: 'owner-1',
      publicKey: owner.publicKey,
      privateKey: await importRsaPrivateKey(owner.privateKey),
      salt: '',
      encryptedPrivateKey: '',
      hasRecoveryKey: true,
    };
    const secretText = JSON.stringify({ name: 'Alarm code', password: '4242' });
    const oldRawKey = await createRandomItemKey();
    const oldCiphertext = await encryptText(secretText, await importAesKey(oldRawKey));
    let revocation:
      | { url: string; body: { ciphertext: string; wrappedKeys: Array<{ userId: string; publicKey: string; wrappedKey: string }> } }
      | undefined;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === '/api/items/item-1') {
          return Response.json({ id: 'item-1', ciphertext: oldCiphertext, wrappedKey: await wrapItemKey(oldRawKey, owner.publicKey) });
        }
        if (url === '/api/items/item-1/shares' && !init?.method) {
          return Response.json({
            users: [
              // The server-provided owner key is ignored in favour of the session's own.
              { userId: 'owner-1', email: 'me@example.com', publicKey: bob.publicKey, sharedAt: '' },
              { userId: 'bob-1', email: 'bob@example.com', publicKey: bob.publicKey, sharedAt: '' },
              { userId: 'carol-1', email: 'carol@example.com', publicKey: carol.publicKey, sharedAt: '' },
            ],
          });
        }
        if (init?.method === 'DELETE') {
          revocation = { url, body: JSON.parse(String(init.body)) };
          return new Response(null, { status: 204 });
        }
        throw new Error(`Unexpected API call: ${url}`);
      }),
    );

    await revokeVaultItemAccess('item-1', 'bob-1', session);

    expect(revocation?.url).toBe('/api/items/item-1/shares/bob-1');
    const { ciphertext, wrappedKeys } = revocation?.body ?? { ciphertext: '', wrappedKeys: [] };
    expect(wrappedKeys.map((entry) => entry.userId)).toEqual(['owner-1', 'carol-1']);
    expect(wrappedKeys.map((entry) => entry.publicKey)).toEqual([owner.publicKey, carol.publicKey]);
    for (const [entry, keys] of [[wrappedKeys[0], owner], [wrappedKeys[1], carol]] as const) {
      const raw = await unwrapItemKey(entry?.wrappedKey ?? '', await importRsaPrivateKey(keys.privateKey));
      expect(await decryptText(ciphertext, await importAesKey(raw))).toBe(secretText);
    }
    // The key bob may have kept does not open the new version.
    await expect(decryptText(ciphertext, await importAesKey(oldRawKey))).rejects.toThrow();
  }, 30_000);
});
