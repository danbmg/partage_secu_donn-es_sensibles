import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { createSession } from '../src/auth/session.js';
import { createApp } from '../src/app.js';
import { openDatabase } from '../src/db.js';

const ciphertext = JSON.stringify({ iv: Buffer.alloc(12, 1).toString('base64'), ciphertext: Buffer.alloc(48, 2).toString('base64') });
const ownerWrappedKey = Buffer.alloc(384, 3).toString('base64');
const recipientWrappedKey = Buffer.alloc(384, 4).toString('base64');
const databases: ReturnType<typeof openDatabase>[] = [];

function fixture() {
  const database = openDatabase(':memory:');
  databases.push(database);
  const app = createApp(database);
  for (const [id, email] of [['owner', 'owner@example.com'], ['other', 'other@example.com']]) {
    database.prepare('INSERT INTO users (id, email, kdf_salt, auth_hash) VALUES (?, ?, ?, ?)').run(id, email, 'salt', 'hash');
  }
  database.prepare('INSERT INTO items (id, owner_id, ciphertext) VALUES (?, ?, ?)').run('item-1', 'owner', ciphertext);
  database.prepare('INSERT INTO item_keys (item_id, user_id, wrapped_key) VALUES (?, ?, ?)').run('item-1', 'owner', ownerWrappedKey);
  return { app, database, ownerToken: createSession('owner'), otherToken: createSession('other') };
}

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

describe('encrypted item sharing', () => {
  it('stores a recipient-wrapped key and lets that recipient read only ciphertext', async () => {
    const { app: testApp, database, ownerToken, otherToken } = fixture();
    const response = await request(testApp)
      .post('/api/items/item-1/shares')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ email: 'other@example.com', wrappedKey: recipientWrappedKey });

    expect(response.status).toBe(201);
    expect(response.body).toEqual({ sharedWithUserId: 'other' });
    expect(database.prepare('SELECT user_id, wrapped_key FROM item_keys WHERE item_id = ? ORDER BY user_id').all('item-1')).toEqual([
      { user_id: 'other', wrapped_key: recipientWrappedKey },
      { user_id: 'owner', wrapped_key: ownerWrappedKey },
    ]);
    const recipientRead = await request(testApp).get('/api/items/item-1').set('Authorization', `Bearer ${otherToken}`);
    expect(recipientRead.status).toBe(200);
    expect(recipientRead.body).toMatchObject({ ciphertext, wrappedKey: recipientWrappedKey, ownerId: 'owner' });
    expect(recipientRead.body).not.toHaveProperty('password');
  });

  it('lists access for the owner and rejects duplicate shares or non-owner share attempts', async () => {
    const { app: testApp, database, ownerToken, otherToken } = fixture();
    const ownerList = await request(testApp).get('/api/items/item-1/shares').set('Authorization', `Bearer ${ownerToken}`);
    expect(ownerList.body.users).toEqual([{ userId: 'owner', email: 'owner@example.com', sharedAt: expect.any(String) }]);

    const share = () => request(testApp).post('/api/items/item-1/shares')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ email: 'other@example.com', wrappedKey: recipientWrappedKey });
    expect((await share()).status).toBe(201);
    expect((await share()).status).toBe(409);
    expect(
      (await request(testApp).post('/api/items/item-1/shares').set('Authorization', `Bearer ${otherToken}`).send({
        email: 'owner@example.com', wrappedKey: recipientWrappedKey,
      })).status,
    ).toBe(404);
    expect((await request(testApp).get('/api/items/item-1/shares').set('Authorization', `Bearer ${otherToken}`)).status).toBe(404);

    const updatedList = await request(testApp).get('/api/items/item-1/shares').set('Authorization', `Bearer ${ownerToken}`);
    expect(updatedList.body.users.map((user: { email: string }) => user.email)).toEqual(['owner@example.com', 'other@example.com']);
    expect(database.prepare("SELECT action FROM audit_log WHERE action = 'share'").all()).toHaveLength(1);
  });

  it('rejects sharing with unknown users and malformed wrapped keys', async () => {
    const { app: testApp, ownerToken } = fixture();
    const url = '/api/items/item-1/shares';
    expect((await request(testApp).post(url).set('Authorization', `Bearer ${ownerToken}`).send({ email: 'nobody@example.com', wrappedKey: recipientWrappedKey })).status).toBe(404);
    expect((await request(testApp).post(url).set('Authorization', `Bearer ${ownerToken}`).send({ email: 'other@example.com', wrappedKey: 'plain secret' })).status).toBe(400);
  });
});
