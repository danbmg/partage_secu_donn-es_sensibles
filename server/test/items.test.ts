import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { createSession } from '../src/auth/session.js';
import { createApp } from '../src/app.js';
import { openDatabase } from '../src/db.js';

const ciphertext = JSON.stringify({ iv: Buffer.alloc(12, 1).toString('base64'), ciphertext: Buffer.alloc(48, 2).toString('base64') });
const updatedCiphertext = JSON.stringify({ iv: Buffer.alloc(12, 3).toString('base64'), ciphertext: Buffer.alloc(48, 4).toString('base64') });
const wrappedKey = Buffer.alloc(384, 5).toString('base64');
const databases: ReturnType<typeof openDatabase>[] = [];

function fixture() {
  const database = openDatabase(':memory:');
  databases.push(database);
  const app = createApp(database);
  database
    .prepare('INSERT INTO users (id, email, kdf_salt, auth_hash) VALUES (?, ?, ?, ?)')
    .run('owner', 'owner@example.com', 'salt', 'hash');
  database
    .prepare('INSERT INTO users (id, email, kdf_salt, auth_hash) VALUES (?, ?, ?, ?)')
    .run('other', 'other@example.com', 'salt', 'hash');
  return {
    app,
    database,
    ownerToken: createSession('owner'),
    otherToken: createSession('other'),
  };
}

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

describe('encrypted vault items', () => {
  it('requires a valid session and accepts only encrypted payload fields', async () => {
    const { app: testApp, database, ownerToken } = fixture();
    expect((await request(testApp).get('/api/items')).status).toBe(401);
    expect(
      (await request(testApp).post('/api/items').set('Authorization', `Bearer ${ownerToken}`).send({ password: 'plain' })).status,
    ).toBe(400);

    const response = await request(testApp)
      .post('/api/items')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ ciphertext, wrappedKey });

    expect(response.status).toBe(201);
    const stored = database.prepare('SELECT * FROM items').get() as Record<string, unknown>;
    expect(stored.ciphertext).toBe(ciphertext);
    expect(stored).not.toHaveProperty('password');
    expect(database.prepare('SELECT wrapped_key FROM item_keys').get()).toEqual({ wrapped_key: wrappedKey });
    expect(database.prepare('SELECT action FROM audit_log').get()).toEqual({ action: 'create' });
  });

  it('lists and reads only items for which the caller has a wrapped key', async () => {
    const { app: testApp, database, ownerToken, otherToken } = fixture();
    const created = await request(testApp).post('/api/items').set('Authorization', `Bearer ${ownerToken}`).send({ ciphertext, wrappedKey });
    const id = created.body.id as string;

    expect((await request(testApp).get('/api/items').set('Authorization', `Bearer ${otherToken}`)).body.items).toHaveLength(0);
    expect((await request(testApp).get(`/api/items/${id}`).set('Authorization', `Bearer ${otherToken}`)).status).toBe(404);
    const ownList = await request(testApp).get('/api/items').set('Authorization', `Bearer ${ownerToken}`);
    expect(ownList.body.items[0]).toMatchObject({ id, ciphertext, wrappedKey, ownerId: 'owner' });
    expect((await request(testApp).get(`/api/items/${id}`).set('Authorization', `Bearer ${ownerToken}`)).body.ciphertext).toBe(ciphertext);
    expect(database.prepare('SELECT action FROM audit_log WHERE action = ?').all('read')).toHaveLength(3);
  });

  it('allows the owner to replace ciphertext and prevents others from editing or deleting', async () => {
    const { app: testApp, database, ownerToken, otherToken } = fixture();
    const { body } = await request(testApp).post('/api/items').set('Authorization', `Bearer ${ownerToken}`).send({ ciphertext, wrappedKey });
    const url = `/api/items/${body.id as string}`;

    expect((await request(testApp).put(url).set('Authorization', `Bearer ${ownerToken}`).send({ ciphertext: updatedCiphertext })).status).toBe(200);
    expect((await request(testApp).put(url).set('Authorization', `Bearer ${otherToken}`).send({ ciphertext })).status).toBe(404);
    expect((await request(testApp).delete(url).set('Authorization', `Bearer ${otherToken}`)).status).toBe(404);
    expect((database.prepare('SELECT ciphertext FROM items WHERE id = ?').get(body.id) as { ciphertext: string }).ciphertext).toBe(updatedCiphertext);
    expect((await request(testApp).delete(url).set('Authorization', `Bearer ${ownerToken}`)).status).toBe(204);
    expect(database.prepare('SELECT id FROM items').all()).toHaveLength(0);
    expect(database.prepare("SELECT action, item_id FROM audit_log WHERE action = 'delete'").get()).toEqual({ action: 'delete', item_id: null });
  });
});
