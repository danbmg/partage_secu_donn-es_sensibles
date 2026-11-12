import { afterEach, describe, expect, it, vi } from 'vitest';
import { importRsaPrivateKey, generateRsaKeyPair } from './crypto/index.js';
import { createVaultItem, readVaultItems, type VaultSecret } from './vault.js';
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
});
