import { randomUUID } from 'node:crypto';
import { Router, type Request, type Response } from 'express';
import type Database from 'better-sqlite3';
import { recordAudit } from '../audit.js';
import { requestUserId } from '../auth/require-session.js';

interface ItemRow {
  id: string;
  owner_id: string;
  ciphertext: string;
  wrapped_key: string;
  created_at: string;
  updated_at: string;
}

function validCiphertext(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 900_000) return false;
  try {
    const envelope: unknown = JSON.parse(value);
    return (
      typeof envelope === 'object' &&
      envelope !== null &&
      typeof (envelope as Record<string, unknown>).iv === 'string' &&
      typeof (envelope as Record<string, unknown>).ciphertext === 'string'
    );
  } catch {
    return false;
  }
}

function validWrappedKey(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const decoded = Buffer.from(value, 'base64');
  return decoded.length >= 256 && decoded.length <= 1024 && decoded.toString('base64') === value;
}

interface WrappedKeyEntry {
  userId: string;
  wrappedKey: string;
}

function validWrappedKeyList(value: unknown): value is WrappedKeyEntry[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 500) return false;
  const seen = new Set<string>();
  for (const entry of value as unknown[]) {
    if (typeof entry !== 'object' || entry === null) return false;
    const { userId, wrappedKey } = entry as Record<string, unknown>;
    if (typeof userId !== 'string' || seen.has(userId) || !validWrappedKey(wrappedKey)) return false;
    seen.add(userId);
  }
  return true;
}

function serialize(row: ItemRow) {
  return {
    id: row.id,
    ownerId: row.owner_id,
    ciphertext: row.ciphertext,
    wrappedKey: row.wrapped_key,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function itemRoutes(database: Database.Database): Router {
  const router = Router();

  router.post('/', (request: Request, response: Response) => {
    const userId = requestUserId(database, request);
    if (!userId) {
      response.status(401).json({ error: 'Authentication required' });
      return;
    }
    const { ciphertext, wrappedKey } = request.body ?? {};
    if (!validCiphertext(ciphertext) || !validWrappedKey(wrappedKey)) {
      response.status(400).json({ error: 'Invalid encrypted item' });
      return;
    }

    const itemId = randomUUID();
    const createItem = database.transaction(() => {
      database.prepare('INSERT INTO items (id, owner_id, ciphertext) VALUES (?, ?, ?)').run(itemId, userId, ciphertext);
      database.prepare('INSERT INTO item_keys (item_id, user_id, wrapped_key) VALUES (?, ?, ?)').run(itemId, userId, wrappedKey);
      recordAudit(database, { userId, itemId, action: 'create' });
    });
    createItem();
    response.status(201).json({ id: itemId });
  });

  router.post('/:id/shares', (request: Request, response: Response) => {
    const userId = requestUserId(database, request);
    if (!userId) {
      response.status(401).json({ error: 'Authentication required' });
      return;
    }
    const emailValue = request.body?.email;
    const email = typeof emailValue === 'string' ? emailValue.trim().toLowerCase() : '';
    const { wrappedKey } = request.body ?? {};
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !validWrappedKey(wrappedKey)) {
      response.status(400).json({ error: 'Invalid sharing data' });
      return;
    }
    const shareItem = database.transaction(() => {
      const item = database
        .prepare('SELECT id FROM items WHERE id = ? AND owner_id = ?')
        .get(request.params.id, userId);
      if (!item) return { status: 'missing-item' as const };
      const recipient = database.prepare('SELECT id FROM users WHERE email = ?').get(email) as { id: string } | undefined;
      if (!recipient) return { status: 'missing-recipient' as const };
      if (recipient.id === userId) return { status: 'self-share' as const };
      try {
        database
          .prepare('INSERT INTO item_keys (item_id, user_id, wrapped_key) VALUES (?, ?, ?)')
          .run(request.params.id, recipient.id, wrappedKey);
      } catch (error) {
        if (error instanceof Error && error.message.includes('UNIQUE constraint failed')) {
          return { status: 'already-shared' as const };
        }
        throw error;
      }
      recordAudit(database, { userId, itemId: String(request.params.id), targetUserId: recipient.id, action: 'share' });
      return { status: 'shared' as const, recipientId: recipient.id };
    });
    const result = shareItem();
    if (result.status === 'missing-item') {
      response.status(404).json({ error: 'Item not found' });
      return;
    }
    if (result.status === 'missing-recipient') {
      response.status(404).json({ error: 'Recipient not found' });
      return;
    }
    if (result.status === 'self-share') {
      response.status(400).json({ error: 'Cannot share an item with yourself' });
      return;
    }
    if (result.status === 'already-shared') {
      response.status(409).json({ error: 'Item is already shared with this user' });
      return;
    }
    response.status(201).json({ sharedWithUserId: result.recipientId });
  });

  router.get('/:id/shares', (request: Request, response: Response) => {
    const userId = requestUserId(database, request);
    if (!userId) {
      response.status(401).json({ error: 'Authentication required' });
      return;
    }
    const owner = database
      .prepare('SELECT id FROM items WHERE id = ? AND owner_id = ?')
      .get(request.params.id, userId);
    if (!owner) {
      response.status(404).json({ error: 'Item not found' });
      return;
    }
    const users = database
      .prepare(
        `SELECT u.id AS userId, u.email, u.public_key AS publicKey, k.created_at AS sharedAt
         FROM item_keys k JOIN users u ON u.id = k.user_id
         WHERE k.item_id = ? ORDER BY k.created_at, k.rowid`,
      )
      .all(request.params.id);
    response.status(200).json({ users });
  });

  // Revocation = remove one access AND change the item key. The browser of the owner
  // sends the item re-encrypted under a new key, wrapped for every remaining holder:
  // a key the revoked user may have kept no longer opens anything.
  router.delete('/:id/shares/:userId', (request: Request, response: Response) => {
    const userId = requestUserId(database, request);
    if (!userId) {
      response.status(401).json({ error: 'Authentication required' });
      return;
    }
    const { ciphertext, wrappedKeys } = request.body ?? {};
    if (!validCiphertext(ciphertext) || !validWrappedKeyList(wrappedKeys)) {
      response.status(400).json({ error: 'Invalid revocation data' });
      return;
    }
    const itemId = String(request.params.id);
    const revokedId = String(request.params.userId);

    const revoke = database.transaction(() => {
      const item = database.prepare('SELECT owner_id FROM items WHERE id = ? AND owner_id = ?').get(itemId, userId);
      if (!item) return 'missing-item' as const;
      if (revokedId === userId) return 'owner' as const;
      const holders = (
        database.prepare('SELECT user_id FROM item_keys WHERE item_id = ?').all(itemId) as Array<{ user_id: string }>
      ).map((row) => row.user_id);
      if (!holders.includes(revokedId)) return 'missing-access' as const;

      // The new key must reach exactly the remaining holders: nobody forgotten
      // (they would lose the item), nobody added through the back door.
      const remaining = new Set(holders.filter((holder) => holder !== revokedId));
      const provided = new Set(wrappedKeys.map((entry) => entry.userId));
      if (remaining.size !== provided.size || [...remaining].some((holder) => !provided.has(holder))) {
        return 'stale-access-list' as const;
      }

      database.prepare('DELETE FROM item_keys WHERE item_id = ? AND user_id = ?').run(itemId, revokedId);
      database
        .prepare("UPDATE items SET ciphertext = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?")
        .run(ciphertext, itemId);
      const updateKey = database.prepare('UPDATE item_keys SET wrapped_key = ? WHERE item_id = ? AND user_id = ?');
      for (const entry of wrappedKeys) updateKey.run(entry.wrappedKey, itemId, entry.userId);
      recordAudit(database, { userId, itemId, targetUserId: revokedId, action: 'revoke' });
      return 'revoked' as const;
    });

    const result = revoke();
    if (result === 'missing-item') {
      response.status(404).json({ error: 'Item not found' });
    } else if (result === 'owner') {
      response.status(400).json({ error: 'The owner cannot revoke their own access' });
    } else if (result === 'missing-access') {
      response.status(404).json({ error: 'This user has no access to the item' });
    } else if (result === 'stale-access-list') {
      response.status(409).json({ error: 'The access list changed, reload and try again' });
    } else {
      response.status(204).end();
    }
  });

  router.get('/', (request: Request, response: Response) => {
    const userId = requestUserId(database, request);
    if (!userId) {
      response.status(401).json({ error: 'Authentication required' });
      return;
    }
    const rows = database
      .prepare(
        `SELECT i.id, i.owner_id, i.ciphertext, k.wrapped_key, i.created_at, i.updated_at
         FROM items i JOIN item_keys k ON k.item_id = i.id
         WHERE k.user_id = ? ORDER BY i.created_at DESC`,
      )
      .all(userId) as ItemRow[];
    const logReads = database.transaction(() => {
      for (const row of rows) recordAudit(database, { userId, itemId: row.id, action: 'read' });
    });
    logReads();
    response.status(200).json({ items: rows.map(serialize) });
  });

  router.get('/:id', (request: Request, response: Response) => {
    const userId = requestUserId(database, request);
    if (!userId) {
      response.status(401).json({ error: 'Authentication required' });
      return;
    }
    const row = database
      .prepare(
        `SELECT i.id, i.owner_id, i.ciphertext, k.wrapped_key, i.created_at, i.updated_at
         FROM items i JOIN item_keys k ON k.item_id = i.id
         WHERE i.id = ? AND k.user_id = ?`,
      )
      .get(request.params.id, userId) as ItemRow | undefined;
    if (!row) {
      response.status(404).json({ error: 'Item not found' });
      return;
    }
    recordAudit(database, { userId, itemId: row.id, action: 'read' });
    response.status(200).json(serialize(row));
  });

  router.put('/:id', (request: Request, response: Response) => {
    const userId = requestUserId(database, request);
    if (!userId) {
      response.status(401).json({ error: 'Authentication required' });
      return;
    }
    const { ciphertext } = request.body ?? {};
    if (!validCiphertext(ciphertext)) {
      response.status(400).json({ error: 'Invalid encrypted item' });
      return;
    }
    const result = database
      .prepare("UPDATE items SET ciphertext = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ? AND owner_id = ?")
      .run(ciphertext, request.params.id, userId);
    if (result.changes === 0) {
      response.status(404).json({ error: 'Item not found' });
      return;
    }
    recordAudit(database, { userId, itemId: String(request.params.id), action: 'update' });
    response.status(200).json({ updated: true });
  });

  router.delete('/:id', (request: Request, response: Response) => {
    const userId = requestUserId(database, request);
    if (!userId) {
      response.status(401).json({ error: 'Authentication required' });
      return;
    }
    const deleteItem = database.transaction(() => {
      const owner = database.prepare('SELECT id FROM items WHERE id = ? AND owner_id = ?').get(request.params.id, userId);
      if (!owner) return false;
      recordAudit(database, { userId, itemId: String(request.params.id), action: 'delete' });
      database.prepare('DELETE FROM items WHERE id = ?').run(request.params.id);
      return true;
    });
    if (!deleteItem()) {
      response.status(404).json({ error: 'Item not found' });
      return;
    }
    response.status(204).end();
  });

  return router;
}
