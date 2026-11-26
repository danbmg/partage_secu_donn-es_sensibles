import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { FailureLimiter } from '../src/auth/rate-limit.js';
import { createApp } from '../src/app.js';
import { openDatabase } from '../src/db.js';

const b64 = (length: number, fill: number) => Buffer.alloc(length, fill).toString('base64');
const envelope = (fill: number) => JSON.stringify({ iv: b64(12, fill), ciphertext: b64(32, fill) });
const account = {
  email: 'alice@example.com',
  salt: b64(16, 1),
  authHash: b64(32, 2),
  publicKey: b64(400, 3),
  encryptedPrivateKey: envelope(4),
  recoveryAuthHash: b64(32, 5),
  recoveryEncryptedPrivateKey: envelope(6),
};
const wrongProof = b64(32, 99);
const databases: ReturnType<typeof openDatabase>[] = [];

async function appWithAccount(limiter?: FailureLimiter) {
  const database = openDatabase(':memory:');
  databases.push(database);
  const app = createApp(database, limiter);
  expect((await request(app).post('/api/register').send(account)).status).toBe(201);
  return app;
}

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

describe('failure limiter', () => {
  it('blocks a key after the maximum number of failures until the window has passed', () => {
    let now = 0;
    const limiter = new FailureLimiter(3, 60_000, () => now);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      expect(limiter.retryAfter('k')).toBe(0);
      limiter.recordFailure('k');
      now += 1_000;
    }
    expect(limiter.retryAfter('k')).toBe(57);
    expect(limiter.retryAfter('other')).toBe(0);
    now = 60_001;
    expect(limiter.retryAfter('k')).toBe(0);

    limiter.recordFailure('k');
    limiter.reset('k');
    expect(limiter.retryAfter('k')).toBe(0);
  });
});

describe('rate limiting on the API', () => {
  it('answers 429 after 5 wrong passwords, even to the right one, and only for that account', async () => {
    let now = 0;
    const app = await appWithAccount(new FailureLimiter(5, 15 * 60_000, () => now));
    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect((await request(app).post('/api/login').send({ email: account.email, authHash: wrongProof })).status).toBe(401);
    }
    const blocked = await request(app).post('/api/login').send({ email: account.email, authHash: account.authHash });
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers['retry-after'])).toBeGreaterThan(0);
    expect((await request(app).post('/api/login').send({ email: 'bob@example.com', authHash: wrongProof })).status).toBe(401);

    now = 15 * 60_000 + 1;
    expect((await request(app).post('/api/login').send({ email: account.email, authHash: account.authHash })).status).toBe(200);
  }, 60_000);

  it('forgets earlier failures after a successful login', async () => {
    const app = await appWithAccount();
    const attempt = (authHash: string) => request(app).post('/api/login').send({ email: account.email, authHash });
    for (let index = 0; index < 4; index += 1) expect((await attempt(wrongProof)).status).toBe(401);
    expect((await attempt(account.authHash)).status).toBe(200);
    for (let index = 0; index < 4; index += 1) expect((await attempt(wrongProof)).status).toBe(401);
    expect((await attempt(account.authHash)).status).toBe(200);
  }, 60_000);

  it('limits recovery key guesses and master password checks behind a session', async () => {
    const app = await appWithAccount();
    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect((await request(app).post('/api/recovery/key').send({ email: account.email, recoveryAuthHash: wrongProof })).status).toBe(401);
    }
    expect(
      (await request(app).post('/api/recovery/key').send({ email: account.email, recoveryAuthHash: account.recoveryAuthHash })).status,
    ).toBe(429);

    const token = (await request(app).post('/api/login').send({ email: account.email, authHash: account.authHash })).body.token as string;
    const update = { authHash: wrongProof, recoveryAuthHash: b64(32, 7), recoveryEncryptedPrivateKey: envelope(8) };
    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect((await request(app).put('/api/account/recovery').set('Authorization', `Bearer ${token}`).send(update)).status).toBe(403);
    }
    expect(
      (await request(app).put('/api/account/recovery').set('Authorization', `Bearer ${token}`).send({ ...update, authHash: account.authHash })).status,
    ).toBe(429);
  }, 60_000);
});
