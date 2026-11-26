import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { hashAuthenticationProof } from '../src/auth/password-proof.js';
import { createSession } from '../src/auth/session.js';
import { createApp } from '../src/app.js';
import { openDatabase } from '../src/db.js';

const b64 = (length: number, fill: number) => Buffer.alloc(length, fill).toString('base64');
const envelope = (fill: number) => JSON.stringify({ iv: b64(12, fill), ciphertext: b64(32, fill) });
const authHash = b64(32, 1);
const oldRecoveryProof = b64(32, 2);
const databases: ReturnType<typeof openDatabase>[] = [];

function fixture() {
  const database = openDatabase(':memory:');
  databases.push(database);
  const addUser = database.prepare(
    `INSERT INTO users (id, email, kdf_salt, auth_hash, public_key, encrypted_private_key,
                        recovery_auth_hash, recovery_encrypted_private_key)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  addUser.run('alice', 'alice@example.com', b64(16, 3), hashAuthenticationProof(authHash), b64(400, 4), envelope(5), hashAuthenticationProof(oldRecoveryProof), envelope(6));
  addUser.run('bob', 'bob@example.com', b64(16, 7), hashAuthenticationProof(b64(32, 8)), b64(400, 9), envelope(10), null, null);
  database.prepare('INSERT INTO items (id, owner_id, ciphertext) VALUES (?, ?, ?)').run('alice-item', 'alice', envelope(11));
  database.prepare('INSERT INTO items (id, owner_id, ciphertext) VALUES (?, ?, ?)').run('bob-item', 'bob', envelope(12));
  const grant = database.prepare('INSERT INTO item_keys (item_id, user_id, wrapped_key) VALUES (?, ?, ?)');
  grant.run('alice-item', 'alice', b64(384, 13));
  grant.run('bob-item', 'bob', b64(384, 14));
  grant.run('bob-item', 'alice', b64(384, 15));
  return { app: createApp(database), database };
}

const rotation = {
  authHash,
  publicKey: b64(400, 20),
  encryptedPrivateKey: envelope(21),
  recoveryAuthHash: b64(32, 22),
  recoveryEncryptedPrivateKey: envelope(23),
  wrappedKeys: [
    { itemId: 'alice-item', wrappedKey: b64(384, 24) },
    { itemId: 'bob-item', wrappedKey: b64(384, 25) },
  ],
};

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

describe('account key rotation', () => {
  it('swaps the key pair, re-wraps every held item key, renews recovery and closes the other sessions', async () => {
    const { app, database } = fixture();
    const current = createSession(database, 'alice');
    const otherDevice = createSession(database, 'alice');
    const bobSession = createSession(database, 'bob');

    const response = await request(app).post('/api/account/rotate-keys').set('Authorization', `Bearer ${current}`).send(rotation);
    expect(response.status).toBe(204);

    expect(database.prepare("SELECT public_key, encrypted_private_key, recovery_encrypted_private_key FROM users WHERE id = 'alice'").get()).toEqual({
      public_key: rotation.publicKey,
      encrypted_private_key: rotation.encryptedPrivateKey,
      recovery_encrypted_private_key: rotation.recoveryEncryptedPrivateKey,
    });
    expect(database.prepare('SELECT item_id, user_id, wrapped_key FROM item_keys ORDER BY item_id, user_id').all()).toEqual([
      { item_id: 'alice-item', user_id: 'alice', wrapped_key: b64(384, 24) },
      { item_id: 'bob-item', user_id: 'alice', wrapped_key: b64(384, 25) },
      { item_id: 'bob-item', user_id: 'bob', wrapped_key: b64(384, 14) },
    ]);
    expect((await request(app).get('/api/users/alice@example.com/public-key')).body.publicKey).toBe(rotation.publicKey);

    expect((await request(app).get('/api/items').set('Authorization', `Bearer ${current}`)).status).toBe(200);
    expect((await request(app).get('/api/items').set('Authorization', `Bearer ${otherDevice}`)).status).toBe(401);
    expect((await request(app).get('/api/items').set('Authorization', `Bearer ${bobSession}`)).status).toBe(200);

    const email = 'alice@example.com';
    expect((await request(app).post('/api/recovery/key').send({ email, recoveryAuthHash: oldRecoveryProof })).status).toBe(401);
    expect((await request(app).post('/api/recovery/key').send({ email, recoveryAuthHash: rotation.recoveryAuthHash })).status).toBe(200);
    expect(database.prepare("SELECT action FROM audit_log WHERE action = 'rotate-keys'").all()).toHaveLength(1);
  }, 30_000);

  it('refuses a wrong master password proof and an incomplete or foreign item key list, changing nothing', async () => {
    const { app, database } = fixture();
    const auth = { Authorization: `Bearer ${createSession(database, 'alice')}` };
    const url = '/api/account/rotate-keys';
    const before = database.prepare('SELECT * FROM item_keys ORDER BY item_id, user_id').all();

    expect((await request(app).post(url).send(rotation)).status).toBe(401);
    expect((await request(app).post(url).set(auth).send({ ...rotation, authHash: b64(32, 99) })).status).toBe(403);
    expect((await request(app).post(url).set(auth).send({ ...rotation, wrappedKeys: rotation.wrappedKeys.slice(0, 1) })).status).toBe(409);
    expect(
      (await request(app).post(url).set(auth).send({
        ...rotation,
        wrappedKeys: [rotation.wrappedKeys[0], { itemId: 'someone-else-item', wrappedKey: b64(384, 26) }],
      })).status,
    ).toBe(409);
    expect((await request(app).post(url).set(auth).send({ ...rotation, masterPassword: 'nope' })).status).toBe(400);
    expect((await request(app).post(url).set(auth).send({ ...rotation, publicKey: 'short' })).status).toBe(400);

    expect(database.prepare('SELECT * FROM item_keys ORDER BY item_id, user_id').all()).toEqual(before);
    expect((database.prepare("SELECT public_key FROM users WHERE id = 'alice'").get() as { public_key: string }).public_key).toBe(b64(400, 4));
  }, 30_000);
});
