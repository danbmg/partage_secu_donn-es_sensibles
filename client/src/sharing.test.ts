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
import { shareVaultItem } from './sharing.js';

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
    expect(JSON.stringify(sharePayload)).not.toContain('never sent as plaintext');
    const recipientPrivateKey = await importRsaPrivateKey(recipientKeys.privateKey);
    const recipientRawKey = await unwrapItemKey(sharePayload?.wrappedKey ?? '', recipientPrivateKey);
    const recipientAesKey = await importAesKey(recipientRawKey);
    expect(await decryptText(ciphertext, recipientAesKey)).toBe(secretText);
  }, 15_000);
});
