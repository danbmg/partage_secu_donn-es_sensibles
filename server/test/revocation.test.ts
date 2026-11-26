import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { createSession } from '../src/auth/session.js';
import { createApp } from '../src/app.js';
import { openDatabase } from '../src/db.js';

const envelope = (fill: number) =>
  JSON.stringify({ iv: Buffer.alloc(12, fill).toString('base64'), ciphertext: Buffer.alloc(48, fill).toString('base64') });
const wrapped = (fill: number) => Buffer.alloc(384, fill).toString('base64');
const databases: ReturnType<typeof openDatabase>[] = [];

function fixture() {
  const database = openDatabase(':memory:');
  databases.push(database);
  for (const id of ['owner', 'bob', 'carol', 'dave']) {
    database
      .prepare('INSERT INTO users (id, email, kdf_salt, auth_hash, public_key) VALUES (?, ?, ?, ?, ?)')
      .run(id, `${id}@example.com`, 'salt', 'hash', `${id}-public-key`);
  }
  database.prepare('INSERT INTO items (id, owner_id, ciphertext) VALUES (?, ?, ?)').run('item-1', 'owner', envelope(1));
  const grant = database.prepare('INSERT INTO item_keys (item_id, user_id, wrapped_key) VALUES (?, ?, ?)');
  grant.run('item-1', 'owner', wrapped(1));
  grant.run('item-1', 'bob', wrapped(2));
  grant.run('item-1', 'carol', wrapped(3));
  const auth = (id: string) => ({ Authorization: `Bearer ${createSession(database, id)}` });
  return { app: createApp(database), database, auth };
}

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

describe('revoking a share', () => {
  it('lists recipients with their public key so the owner can re-wrap a new item key', async () => {
    const { app, auth } = fixture();
    const { body } = await request(app).get('/api/items/item-1/shares').set(auth('owner'));
    expect(body.users.map((user: { userId: string; publicKey: string }) => [user.userId, user.publicKey])).toEqual([
      ['owner', 'owner-public-key'],
      ['bob', 'bob-public-key'],
      ['carol', 'carol-public-key'],
    ]);
  });

  it('removes the access and replaces the ciphertext and every remaining wrapped key at once', async () => {
    const { app, database, auth } = fixture();
    const response = await request(app)
      .delete('/api/items/item-1/shares/bob')
      .set(auth('owner'))
      .send({ ciphertext: envelope(9), wrappedKeys: [{ userId: 'owner', publicKey: 'owner-public-key', wrappedKey: wrapped(10) }, { userId: 'carol', publicKey: 'carol-public-key', wrappedKey: wrapped(11) }] });

    expect(response.status).toBe(204);
    expect((await request(app).get('/api/items/item-1').set(auth('bob'))).status).toBe(404);
    expect((await request(app).get('/api/items').set(auth('bob'))).body.items).toEqual([]);
    expect((await request(app).get('/api/items/item-1').set(auth('carol'))).body).toMatchObject({
      ciphertext: envelope(9),
      wrappedKey: wrapped(11),
    });
    expect(database.prepare('SELECT user_id, wrapped_key FROM item_keys ORDER BY user_id').all()).toEqual([
      { user_id: 'carol', wrapped_key: wrapped(11) },
      { user_id: 'owner', wrapped_key: wrapped(10) },
    ]);
    const log = await request(app).get('/api/audit').set(auth('owner'));
    expect(log.body.entries).toContainEqual(
      expect.objectContaining({ action: 'revoke', itemId: 'item-1', actorId: 'owner', targetEmail: 'bob@example.com' }),
    );
  });

  it('refuses a new key set that forgets a holder or still includes the revoked user, and changes nothing', async () => {
    const { app, database, auth } = fixture();
    const url = '/api/items/item-1/shares/bob';
    const forgetsCarol = [{ userId: 'owner', publicKey: 'owner-public-key', wrappedKey: wrapped(10) }];
    const keepsBob = [...forgetsCarol, { userId: 'carol', publicKey: 'carol-public-key', wrappedKey: wrapped(11) }, { userId: 'bob', publicKey: 'bob-public-key', wrappedKey: wrapped(12) }];
    const addsDave = [...forgetsCarol, { userId: 'dave', publicKey: 'dave-public-key', wrappedKey: wrapped(13) }];

    for (const wrappedKeys of [forgetsCarol, keepsBob, addsDave]) {
      expect((await request(app).delete(url).set(auth('owner')).send({ ciphertext: envelope(9), wrappedKeys })).status).toBe(409);
    }
    expect(database.prepare('SELECT COUNT(*) AS count FROM item_keys').get()).toEqual({ count: 3 });
    expect(database.prepare('SELECT ciphertext FROM items').get()).toEqual({ ciphertext: envelope(1) });
  });

  it('refuses a new key wrapped for a public key a remaining holder no longer has', async () => {
    const { app, database, auth } = fixture();
    const response = await request(app)
      .delete('/api/items/item-1/shares/bob')
      .set(auth('owner'))
      .send({
        ciphertext: envelope(9),
        wrappedKeys: [
          { userId: 'owner', publicKey: 'owner-public-key', wrappedKey: wrapped(10) },
          { userId: 'carol', publicKey: 'carol-key-before-rotation', wrappedKey: wrapped(11) },
        ],
      });
    expect(response.status).toBe(409);
    expect(database.prepare('SELECT COUNT(*) AS count FROM item_keys').get()).toEqual({ count: 3 });
  });

  it('only lets the owner revoke, never their own access, and validates the payload', async () => {
    const { app, auth } = fixture();
    const body = { ciphertext: envelope(9), wrappedKeys: [{ userId: 'owner', publicKey: 'owner-public-key', wrappedKey: wrapped(10) }, { userId: 'bob', publicKey: 'bob-public-key', wrappedKey: wrapped(11) }] };

    expect((await request(app).delete('/api/items/item-1/shares/carol').send(body)).status).toBe(401);
    expect((await request(app).delete('/api/items/item-1/shares/carol').set(auth('bob')).send(body)).status).toBe(404);
    expect((await request(app).delete('/api/items/item-1/shares/owner').set(auth('owner')).send(body)).status).toBe(400);
    expect((await request(app).delete('/api/items/item-1/shares/dave').set(auth('owner')).send(body)).status).toBe(404);
    expect((await request(app).delete('/api/items/item-1/shares/carol').set(auth('owner')).send({ ...body, ciphertext: 'plain' })).status).toBe(400);
    expect(
      (await request(app).delete('/api/items/item-1/shares/carol').set(auth('owner')).send({
        ...body,
        wrappedKeys: [{ userId: 'owner', publicKey: 'owner-public-key', wrappedKey: wrapped(10) }, { userId: 'owner', publicKey: 'owner-public-key', wrappedKey: wrapped(10) }],
      })).status,
    ).toBe(400);
  });
});
