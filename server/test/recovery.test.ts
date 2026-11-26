import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { openDatabase } from '../src/db.js';

const b64 = (length: number, fill: number) => Buffer.alloc(length, fill).toString('base64');
const envelope = (fill: number) => JSON.stringify({ iv: b64(12, fill), ciphertext: b64(32, fill) });
const email = 'alice@example.com';
const account = {
  email,
  salt: b64(16, 1),
  authHash: b64(32, 2),
  publicKey: b64(400, 3),
  encryptedPrivateKey: envelope(4),
  recoveryAuthHash: b64(32, 5),
  recoveryEncryptedPrivateKey: envelope(6),
};
const databases: ReturnType<typeof openDatabase>[] = [];

async function registeredApp() {
  const database = openDatabase(':memory:');
  databases.push(database);
  const app = createApp(database);
  expect((await request(app).post('/api/register').send(account)).status).toBe(201);
  return { app, database };
}

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

describe('account recovery', () => {
  it('requires recovery material at registration', async () => {
    const database = openDatabase(':memory:');
    databases.push(database);
    const { recoveryAuthHash, ...withoutRecovery } = account;
    void recoveryAuthHash;
    expect((await request(createApp(database)).post('/api/register').send(withoutRecovery)).status).toBe(400);
  });

  it('resets the password with the recovery key, rotates the recovery key and closes every session', async () => {
    const { app, database } = await registeredApp();
    const oldToken = (await request(app).post('/api/login').send({ email, authHash: account.authHash })).body.token as string;

    expect((await request(app).post('/api/recovery/key').send({ email, recoveryAuthHash: b64(32, 9) })).status).toBe(401);
    const key = await request(app).post('/api/recovery/key').send({ email, recoveryAuthHash: account.recoveryAuthHash });
    expect(key.status).toBe(200);
    expect(key.body).toEqual({ recoveryEncryptedPrivateKey: account.recoveryEncryptedPrivateKey });

    const reset = {
      email,
      recoveryAuthHash: account.recoveryAuthHash,
      salt: b64(16, 11),
      authHash: b64(32, 12),
      encryptedPrivateKey: envelope(13),
      newRecoveryAuthHash: b64(32, 14),
      newRecoveryEncryptedPrivateKey: envelope(15),
    };
    expect((await request(app).post('/api/recovery/reset').send({ ...reset, recoveryAuthHash: b64(32, 9) })).status).toBe(401);
    expect((await request(app).post('/api/recovery/reset').send(reset)).status).toBe(204);

    expect((await request(app).get('/api/items').set('Authorization', `Bearer ${oldToken}`)).status).toBe(401);
    expect((await request(app).post('/api/login').send({ email, authHash: account.authHash })).status).toBe(401);
    const login = await request(app).post('/api/login').send({ email, authHash: reset.authHash });
    expect(login.status).toBe(200);
    expect(login.body.encryptedPrivateKey).toBe(reset.encryptedPrivateKey);
    expect((await request(app).get('/api/auth/salt').query({ email })).body.salt).toBe(reset.salt);

    // The used recovery key is dead; the new one works.
    expect((await request(app).post('/api/recovery/key').send({ email, recoveryAuthHash: account.recoveryAuthHash })).status).toBe(401);
    expect((await request(app).post('/api/recovery/key').send({ email, recoveryAuthHash: reset.newRecoveryAuthHash })).body).toEqual({
      recoveryEncryptedPrivateKey: reset.newRecoveryEncryptedPrivateKey,
    });
    expect(database.prepare("SELECT action FROM audit_log WHERE action = 'recover'").all()).toHaveLength(1);
  }, 60_000);

  it('replaces the recovery key of a logged-in user only with the master password proof', async () => {
    const { app, database } = await registeredApp();
    const token = (await request(app).post('/api/login').send({ email, authHash: account.authHash })).body.token as string;
    const update = { authHash: account.authHash, recoveryAuthHash: b64(32, 21), recoveryEncryptedPrivateKey: envelope(22) };

    expect((await request(app).put('/api/account/recovery').send(update)).status).toBe(401);
    expect(
      (await request(app).put('/api/account/recovery').set('Authorization', `Bearer ${token}`).send({ ...update, authHash: b64(32, 9) })).status,
    ).toBe(403);
    expect((await request(app).put('/api/account/recovery').set('Authorization', `Bearer ${token}`).send(update)).status).toBe(204);

    expect((await request(app).post('/api/recovery/key').send({ email, recoveryAuthHash: account.recoveryAuthHash })).status).toBe(401);
    expect((await request(app).post('/api/recovery/key').send({ email, recoveryAuthHash: update.recoveryAuthHash })).status).toBe(200);
    expect(database.prepare("SELECT action FROM audit_log WHERE action = 'recovery-update'").all()).toHaveLength(1);
  }, 60_000);

  it('refuses accounts without recovery key and requests carrying the raw recovery key', async () => {
    const { app, database } = await registeredApp();
    database.prepare('UPDATE users SET recovery_auth_hash = NULL, recovery_encrypted_private_key = NULL').run();

    expect((await request(app).post('/api/recovery/key').send({ email, recoveryAuthHash: account.recoveryAuthHash })).status).toBe(401);
    expect((await request(app).post('/api/login').send({ email, authHash: account.authHash })).body.hasRecoveryKey).toBe(false);
    expect(
      (await request(app).post('/api/recovery/key').send({ email, recoveryAuthHash: account.recoveryAuthHash, recoveryKey: 'ABCD' })).status,
    ).toBe(400);
  }, 30_000);
});
