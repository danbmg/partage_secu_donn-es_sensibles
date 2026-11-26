import { afterEach, describe, expect, it, vi } from 'vitest';
import { loginAccount, logoutAccount, registerAccount } from './auth.js';
import { generateRsaKeyPair } from './crypto/index.js';
import { ApiError } from './http.js';

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
          expect(registration).not.toHaveProperty('masterPassword');
          expect(registration).not.toHaveProperty('password');
          expect(registration).not.toHaveProperty('recoveryKey');
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
            hasRecoveryKey: true,
          });
        }
        throw new Error(`Unexpected API call: ${url}`);
      }),
    );

    const created = await registerAccount('alice@example.com', 'a strong master password');
    expect(created.userId).toBe('user-1');
    expect(created.recoveryKey).toMatch(/^([A-Z2-7]{4}-){7}[A-Z2-7]{4}$/);
    expect(JSON.stringify(registration)).not.toContain(created.recoveryKey.replaceAll('-', ''));
    expect(registration?.recoveryAuthHash).toBeTruthy();
    expect(registration?.recoveryEncryptedPrivateKey).not.toBe(registration?.encryptedPrivateKey);
    expect(registration?.encryptedPrivateKey).toBeTruthy();
    expect(registration?.encryptedPrivateKey).not.toContain(registration?.publicKey);
    const session = await loginAccount('alice@example.com', 'a strong master password');

    expect(session.userId).toBe('user-1');
    expect(session.token).toBe('signed-session');
    expect(session.publicKey).toBe(registration?.publicKey);
    expect(session.privateKey.algorithm.name).toBe('RSA-OAEP');
    expect(session.salt).toBe(registration?.salt);
    expect(session.encryptedPrivateKey).toBe(registration?.encryptedPrivateKey);
    expect(session.hasRecoveryKey).toBe(true);
  }, 30_000);

  it('asks the server to drop the session on logout and reports API errors with their status', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      void input;
      return (init?.headers as Record<string, string>).Authorization === 'Bearer live'
        ? new Response(null, { status: 204 })
        : Response.json({ error: 'Authentication required' }, { status: 401 });
    });
    vi.stubGlobal('fetch', fetchMock);
    const session = { token: 'live', userId: 'u', publicKey: '', privateKey: {} as CryptoKey, salt: '', encryptedPrivateKey: '', hasRecoveryKey: true };

    await expect(logoutAccount(session)).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledWith('/api/logout', { method: 'POST', headers: { Authorization: 'Bearer live' } });
    const failure = await logoutAccount({ ...session, token: 'stale' }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ApiError);
    expect(failure).toMatchObject({ status: 401, message: 'Authentication required' });
  });

  it('refuses to log in when the server returns a public key that is not mine', async () => {
    let registration: Record<string, string> | undefined;
    const substitute = await generateRsaKeyPair();
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === '/api/register') {
          registration = JSON.parse(String(init?.body)) as Record<string, string>;
          return Response.json({ userId: 'user-1' }, { status: 201 });
        }
        if (url.startsWith('/api/auth/salt')) return Response.json({ salt: registration?.salt });
        return Response.json({
          token: 'tok',
          userId: 'user-1',
          publicKey: substitute.publicKey,
          encryptedPrivateKey: registration?.encryptedPrivateKey,
          hasRecoveryKey: true,
        });
      }),
    );

    await registerAccount('alice@example.com', 'a strong master password');
    await expect(loginAccount('alice@example.com', 'a strong master password')).rejects.toThrow(
      'Public key does not match private key',
    );
  }, 60_000);
});
