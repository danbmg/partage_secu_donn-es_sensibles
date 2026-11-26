import { afterEach, describe, expect, it, vi } from 'vitest';
import { loginAccount, registerAccount } from './auth.js';
import { decryptText, deriveEncryptionKey, deriveRecoveryEncryptionKey } from './crypto/index.js';
import { recoverAccount, regenerateRecoveryKey } from './recovery.js';

afterEach(() => vi.unstubAllGlobals());

type Body = Record<string, string>;

// A tiny in-memory stand-in for the API: it only stores what the browser sends.
function fakeServer() {
  const state: { account?: Body; reset?: Body; recoveryUpdate?: Body; bodies: string[] } = { bodies: [] };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const body = init?.body ? (JSON.parse(String(init.body)) as Body) : {};
      if (init?.body) state.bodies.push(String(init.body));
      if (url === '/api/register') {
        state.account = body;
        return Response.json({ userId: 'user-1' }, { status: 201 });
      }
      if (url.startsWith('/api/auth/salt')) return Response.json({ salt: state.account?.salt });
      if (url === '/api/login') {
        return Response.json({
          token: 'tok',
          userId: 'user-1',
          publicKey: state.account?.publicKey,
          encryptedPrivateKey: state.account?.encryptedPrivateKey,
          hasRecoveryKey: true,
        });
      }
      if (url === '/api/recovery/key') {
        return body.recoveryAuthHash === state.account?.recoveryAuthHash
          ? Response.json({ recoveryEncryptedPrivateKey: state.account?.recoveryEncryptedPrivateKey })
          : Response.json({ error: 'Invalid email or recovery key' }, { status: 401 });
      }
      if (url === '/api/recovery/reset') {
        state.reset = body;
        return new Response(null, { status: 204 });
      }
      if (url === '/api/account/recovery') {
        state.recoveryUpdate = body;
        return new Response(null, { status: 204 });
      }
      throw new Error(`Unexpected API call: ${url}`);
    }),
  );
  return state;
}

describe('account recovery in the browser', () => {
  it('re-encrypts the same private key under the new password and issues a new recovery key', async () => {
    const server = fakeServer();
    const { recoveryKey } = await registerAccount('alice@example.com', 'the original password');
    const originalPrivateKey = await decryptText(
      server.account?.encryptedPrivateKey ?? '',
      await deriveEncryptionKey('the original password', server.account?.salt ?? ''),
    );

    await expect(recoverAccount('alice@example.com', 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA', 'x')).rejects.toThrow(
      'Invalid email or recovery key',
    );
    const typedByHand = recoveryKey.toLowerCase().replaceAll('-', ' ');
    const newRecoveryKey = await recoverAccount('alice@example.com', typedByHand, 'a brand new password');

    const reset = server.reset ?? {};
    expect(newRecoveryKey).not.toBe(recoveryKey);
    expect(reset.salt).not.toBe(server.account?.salt);
    expect(await decryptText(reset.encryptedPrivateKey ?? '', await deriveEncryptionKey('a brand new password', reset.salt ?? ''))).toBe(
      originalPrivateKey,
    );
    expect(await decryptText(reset.newRecoveryEncryptedPrivateKey ?? '', await deriveRecoveryEncryptionKey(newRecoveryKey))).toBe(
      originalPrivateKey,
    );
    for (const sent of server.bodies) {
      expect(sent).not.toContain('a brand new password');
      expect(sent).not.toContain(recoveryKey.replaceAll('-', ''));
      expect(sent).not.toContain(newRecoveryKey.replaceAll('-', ''));
    }
  }, 60_000);

  it('checks the master password locally before replacing the recovery key', async () => {
    const server = fakeServer();
    await registerAccount('alice@example.com', 'the original password');
    const session = await loginAccount('alice@example.com', 'the original password');

    await expect(regenerateRecoveryKey(session, 'not the password')).rejects.toThrow('Invalid master password');
    expect(server.recoveryUpdate).toBeUndefined();

    const recoveryKey = await regenerateRecoveryKey(session, 'the original password');
    expect(server.recoveryUpdate?.authHash).toBe(server.account?.authHash);
    expect(await decryptText(server.recoveryUpdate?.recoveryEncryptedPrivateKey ?? '', await deriveRecoveryEncryptionKey(recoveryKey))).toBe(
      await decryptText(server.account?.encryptedPrivateKey ?? '', await deriveEncryptionKey('the original password', session.salt)),
    );
  }, 60_000);
});
