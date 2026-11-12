import { randomUUID } from 'node:crypto';
import { Router, type Request, type Response } from 'express';
import type Database from 'better-sqlite3';
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
    const userId = requestUserId(request);
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
      database.prepare("INSERT INTO audit_log (user_id, item_id, action) VALUES (?, ?, 'create')").run(userId, itemId);
    });
    createItem();
    response.status(201).json({ id: itemId });
  });

  router.post('/:id/shares', (request: Request, response: Response) => {
    const userId = requestUserId(request);
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
      database
        .prepare("INSERT INTO audit_log (user_id, item_id, action) VALUES (?, ?, 'share')")
        .run(userId, request.params.id);
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
    const userId = requestUserId(request);
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
        `SELECT u.id AS userId, u.email, k.created_at AS sharedAt
         FROM item_keys k JOIN users u ON u.id = k.user_id
         WHERE k.item_id = ? ORDER BY k.created_at`,
      )
      .all(request.params.id);
    response.status(200).json({ users });
  });

  router.get('/', (request: Request, response: Response) => {
    const userId = requestUserId(request);
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
    database
      .prepare("INSERT INTO audit_log (user_id, action) VALUES (?, 'read')")
      .run(userId);
    response.status(200).json({ items: rows.map(serialize) });
  });

  router.get('/:id', (request: Request, response: Response) => {
    const userId = requestUserId(request);
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
    database
      .prepare("INSERT INTO audit_log (user_id, item_id, action) VALUES (?, ?, 'read')")
      .run(userId, row.id);
    response.status(200).json(serialize(row));
  });

  router.put('/:id', (request: Request, response: Response) => {
    const userId = requestUserId(request);
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
    database
      .prepare("INSERT INTO audit_log (user_id, item_id, action) VALUES (?, ?, 'update')")
      .run(userId, request.params.id);
    response.status(200).json({ updated: true });
  });

  router.delete('/:id', (request: Request, response: Response) => {
    const userId = requestUserId(request);
    if (!userId) {
      response.status(401).json({ error: 'Authentication required' });
      return;
    }
    const deleteItem = database.transaction(() => {
      const owner = database.prepare('SELECT id FROM items WHERE id = ? AND owner_id = ?').get(request.params.id, userId);
      if (!owner) return false;
      database
        .prepare("INSERT INTO audit_log (user_id, item_id, action) VALUES (?, ?, 'delete')")
        .run(userId, request.params.id);
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
