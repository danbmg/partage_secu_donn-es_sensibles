import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { app, createApp } from '../src/app.js';
import { openDatabase } from '../src/db.js';
import { authenticatedUserId } from '../src/auth/session.js';

const salt = Buffer.alloc(16, 7).toString('base64');
const authHash = Buffer.alloc(32, 9).toString('base64');
const anotherAuthHash = Buffer.alloc(32, 3).toString('base64');
const publicKey = Buffer.alloc(400, 4).toString('base64');
const encryptedPrivateKey = JSON.stringify({ iv: Buffer.alloc(12).toString('base64'), ciphertext: Buffer.alloc(32).toString('base64') });
const databases: ReturnType<typeof openDatabase>[] = [];

function newTestApp() {
  const database = openDatabase(':memory:');
  databases.push(database);
  return { app: createApp(database), database };
}

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

describe('account registration and login', () => {
  it('stores a salted server-side rehash of the client-derived authentication value', async () => {
    const { app: testApp, database } = newTestApp();
    const response = await request(testApp).post('/api/register').send({
      email: 'Alice@example.com',
      salt,
      authHash,
      publicKey,
      encryptedPrivateKey,
    });

    expect(response.status).toBe(201);
    expect((await request(testApp).get('/api/auth/salt').query({ email: 'alice@example.com' })).body.salt).toBe(salt);
    expect((await request(testApp).get('/api/users/alice@example.com/public-key')).body.publicKey).toBe(publicKey);
    const user = database.prepare('SELECT * FROM users').get() as Record<string, unknown>;
    expect(user.email).toBe('alice@example.com');
    expect(user.auth_hash).not.toBe(authHash);
    expect(String(user.auth_hash)).toContain(':');
    expect(user).not.toHaveProperty('password');
    expect(user.public_key).toBe(publicKey);
    expect(user.encrypted_private_key).toBe(encryptedPrivateKey);
  }, 15_000);

  it('logs in using only the derived proof and returns a signed session token', async () => {
    const { app: testApp, database } = newTestApp();
    await request(testApp).post('/api/register').send({ email: 'alice@example.com', salt, authHash, publicKey, encryptedPrivateKey });

    const response = await request(testApp).post('/api/login').send({ email: 'alice@example.com', authHash });

    expect(response.status).toBe(200);
    expect(authenticatedUserId(`Bearer ${response.body.token}`)).toBe(response.body.userId);
    expect(response.body.encryptedPrivateKey).toBe(encryptedPrivateKey);
    expect(response.body.publicKey).toBe(publicKey);
    expect(database.prepare("SELECT action FROM audit_log").get()).toEqual({ action: 'login' });
  }, 15_000);

  it('rejects wrong proofs, duplicate accounts, and any request containing a master password', async () => {
    const { app: testApp } = newTestApp();
    const registration = { email: 'alice@example.com', salt, authHash, publicKey, encryptedPrivateKey };
    expect((await request(testApp).post('/api/register').send(registration)).status).toBe(201);
    expect((await request(testApp).post('/api/register').send(registration)).status).toBe(409);
    expect(
      (await request(testApp).post('/api/login').send({ email: registration.email, authHash: anotherAuthHash })).status,
    ).toBe(401);
    expect(
      (await request(testApp).post('/api/login').send({ ...registration, masterPassword: 'not-sent' })).status,
    ).toBe(400);
  }, 30_000);

  it('keeps the health endpoint available', async () => {
    const response = await request(app).get('/api/health');
    expect(response.status).toBe(200);
  });
});
