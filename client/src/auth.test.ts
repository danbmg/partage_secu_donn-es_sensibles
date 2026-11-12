import { afterEach, describe, expect, it, vi } from 'vitest';
import { loginAccount, registerAccount } from './auth.js';

afterEach(() => vi.unstubAllGlobals());

describe('browser account flow', () => {
  it('sends only derived proof and encrypted private key, then decrypts the private key after login', async () => {
    let registration: Record<string, string> | undefined;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === '/api/register') {
          registration = JSON.parse(String(init?.body)) as Record<string, string>;
          return Response.json({ userId: 'user-1' }, { status: 201 });
        }
        if (url.startsWith('/api/auth/salt')) {
          return Response.json({ salt: registration?.salt });
        }
        if (url === '/api/login') {
          const payload = JSON.parse(String(init?.body)) as Record<string, string>;
          expect(payload).not.toHaveProperty('masterPassword');
          expect(payload.authHash).toBe(registration?.authHash);
          return Response.json({
            token: 'signed-session',
            userId: 'user-1',
            publicKey: registration?.publicKey,
            encryptedPrivateKey: registration?.encryptedPrivateKey,
          });
        }
        throw new Error(`Unexpected API call: ${url}`);
      }),
    );

    expect(await registerAccount('alice@example.com', 'a strong master password')).toBe('user-1');
    expect(registration?.encryptedPrivateKey).toBeTruthy();
    expect(registration?.encryptedPrivateKey).not.toContain(registration?.publicKey);
    const session = await loginAccount('alice@example.com', 'a strong master password');

    expect(session.userId).toBe('user-1');
    expect(session.token).toBe('signed-session');
    expect(session.publicKey).toBe(registration?.publicKey);
    expect(session.privateKey.algorithm.name).toBe('RSA-OAEP');
  }, 30_000);
});
