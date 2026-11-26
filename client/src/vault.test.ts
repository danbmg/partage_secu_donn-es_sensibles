import { afterEach, describe, expect, it, vi } from 'vitest';
import { decryptText, importAesKey, importRsaPrivateKey, generateRsaKeyPair, unwrapItemKey } from './crypto/index.js';
import { createVaultItem, deleteVaultItem, readVaultItems, updateVaultItem, type VaultSecret } from './vault.js';
import type { AuthenticatedSession } from './auth.js';

afterEach(() => vi.unstubAllGlobals());

describe('client-side vault encryption', () => {
  it('sends ciphertext and a wrapped key, then decrypts the fetched item in the browser', async () => {
    const keyPair = await generateRsaKeyPair();
    const session: AuthenticatedSession = {
      token: 'session-token',
      userId: 'owner-1',
      publicKey: keyPair.publicKey,
      privateKey: await importRsaPrivateKey(keyPair.privateKey),
      salt: '',
      encryptedPrivateKey: '',
      hasRecoveryKey: true,
    };
    let stored: Record<string, string> | undefined;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === '/api/items' && init?.method === 'POST') {
          stored = JSON.parse(String(init.body)) as Record<string, string>;
          return Response.json({ id: 'item-1' }, { status: 201 });
        }
        if (url === '/api/items' && !init?.method) {
          return Response.json({
            items: [{
              id: 'item-1', ownerId: 'owner-1', ciphertext: stored?.ciphertext,
              wrappedKey: stored?.wrappedKey, createdAt: 'created', updatedAt: 'updated',
            }],
          });
        }
        throw new Error(`Unexpected API call: ${url}`);
      }),
    );

    const secret: VaultSecret = {
      name: 'Production database',
      username: 'app-user',
      password: 'super secret value',
      notes: 'Only client-readable',
    };
    expect(await createVaultItem(secret, session)).toEqual({ id: 'item-1' });
    expect(stored).toBeDefined();
    expect(JSON.stringify(stored)).not.toContain(secret.password);
    expect(JSON.stringify(stored)).not.toContain(secret.name);
    expect(JSON.parse(stored?.ciphertext ?? '{}')).toHaveProperty('iv');

    await expect(readVaultItems(session)).resolves.toEqual([{ ...secret, id: 'item-1', ownerId: 'owner-1', createdAt: 'created', updatedAt: 'updated' }]);
  }, 15_000);

  it('re-encrypts an edited item with its existing key and lets only the owner do it', async () => {
    const keyPair = await generateRsaKeyPair();
    const session: AuthenticatedSession = {
      token: 'session-token',
      userId: 'owner-1',
      publicKey: keyPair.publicKey,
      privateKey: await importRsaPrivateKey(keyPair.privateKey),
      salt: '',
      encryptedPrivateKey: '',
      hasRecoveryKey: true,
    };
    let stored: Record<string, string> = {};
    let owner = 'owner-1';
    const calls: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        calls.push(`${init?.method ?? 'GET'} ${url}`);
        if (url === '/api/items' && init?.method === 'POST') {
          stored = JSON.parse(String(init.body)) as Record<string, string>;
          return Response.json({ id: 'item-1' }, { status: 201 });
        }
        if (url === '/api/items/item-1' && !init?.method) return Response.json({ id: 'item-1', ownerId: owner, ...stored });
        if (url === '/api/items/item-1' && init?.method === 'PUT') {
          stored = { ...stored, ...(JSON.parse(String(init.body)) as Record<string, string>) };
          return Response.json({ updated: true });
        }
        if (url === '/api/items/item-1' && init?.method === 'DELETE') return new Response(null, { status: 204 });
        throw new Error(`Unexpected API call: ${url}`);
      }),
    );

    await createVaultItem({ name: 'Alarm', username: '', password: '1234', notes: '' }, session);
    const originalCiphertext = stored.ciphertext;
    await updateVaultItem('item-1', { name: 'Alarm', username: '', password: '9876', notes: 'changed' }, session);

    expect(stored.ciphertext).not.toBe(originalCiphertext);
    const itemKey = await importAesKey(await unwrapItemKey(stored.wrappedKey ?? '', session.privateKey));
    expect(JSON.parse(await decryptText(stored.ciphertext ?? '', itemKey))).toMatchObject({ password: '9876', notes: 'changed' });

    owner = 'someone-else';
    await expect(updateVaultItem('item-1', { name: 'x', username: '', password: '', notes: '' }, session)).rejects.toThrow(
      'Only the owner can update this item',
    );
    expect(calls.filter((call) => call.startsWith('PUT'))).toHaveLength(1);

    await deleteVaultItem('item-1', session);
    expect(calls.at(-1)).toBe('DELETE /api/items/item-1');
  }, 30_000);
});
