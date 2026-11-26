import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { createSession } from '../src/auth/session.js';
import { createApp } from '../src/app.js';
import { openDatabase } from '../src/db.js';

const ciphertext = JSON.stringify({ iv: Buffer.alloc(12, 1).toString('base64'), ciphertext: Buffer.alloc(48, 2).toString('base64') });
const wrappedKey = Buffer.alloc(384, 3).toString('base64');
const databases: ReturnType<typeof openDatabase>[] = [];

function fixture() {
  const database = openDatabase(':memory:');
  databases.push(database);
  for (const [id, email] of [['owner', 'owner@example.com'], ['other', 'other@example.com'], ['third', 'third@example.com']]) {
    database
      .prepare('INSERT INTO users (id, email, kdf_salt, auth_hash, public_key) VALUES (?, ?, ?, ?, ?)')
      .run(id, email, 'salt', 'hash', `${id}-public-key`);
  }
  return {
    app: createApp(database),
    database,
    ownerToken: createSession(database, 'owner'),
    otherToken: createSession(database, 'other'),
    thirdToken: createSession(database, 'third'),
  };
}

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

describe('audit log', () => {
  it('requires a session', async () => {
    const { app } = fixture();
    expect((await request(app).get('/api/audit')).status).toBe(401);
  });

  it('shows the owner who was given access and who read their item, but hides unrelated activity', async () => {
    const { app, ownerToken, otherToken, thirdToken } = fixture();
    const auth = (token: string) => ({ Authorization: `Bearer ${token}` });
    const { body } = await request(app).post('/api/items').set(auth(ownerToken)).send({ ciphertext, wrappedKey });
    const itemId = body.id as string;
    await request(app).post(`/api/items/${itemId}/shares`).set(auth(ownerToken)).send({ email: 'other@example.com', wrappedKey, recipientPublicKey: 'other-public-key' });
    await request(app).get('/api/items').set(auth(otherToken));
    await request(app).post('/api/items').set(auth(thirdToken)).send({ ciphertext, wrappedKey });

    const ownerLog = await request(app).get('/api/audit').set(auth(ownerToken));
    expect(ownerLog.status).toBe(200);
    expect(ownerLog.body.entries).toEqual([
      expect.objectContaining({ action: 'read', itemId, actorId: 'other', actorEmail: 'other@example.com', targetEmail: null }),
      expect.objectContaining({ action: 'share', itemId, actorId: 'owner', targetEmail: 'other@example.com' }),
      expect.objectContaining({ action: 'create', itemId, actorId: 'owner' }),
    ]);

    // The recipient sees their own read, not the owner's history on the item.
    const otherLog = await request(app).get('/api/audit').set(auth(otherToken));
    expect(otherLog.body.entries.map((entry: { action: string }) => entry.action)).toEqual(['read']);
  });
});
