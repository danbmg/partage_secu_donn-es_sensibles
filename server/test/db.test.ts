import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/db.js';

describe('SQLite schema', () => {
  it('creates the required tables and relationships on initialization', () => {
    const db = openDatabase(':memory:');
    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
      .all()
      .map((row) => (row as { name: string }).name);

    expect(tables).toEqual(['audit_log', 'item_keys', 'items', 'sqlite_sequence', 'users']);
    expect(db.pragma('foreign_keys', { simple: true })).toBe(1);
    expect(db.prepare('PRAGMA table_info(items)').all()).toHaveLength(5);
    db.close();
  });

  it('stores encrypted payloads and wrapped keys, without plaintext secret columns', () => {
    const db = openDatabase(':memory:');
    const columns = ['users', 'items', 'item_keys', 'audit_log'].flatMap((table) =>
      (db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>).map(
        ({ name }) => name.toLowerCase(),
      ),
    );

    expect(columns).not.toContain('password');
    expect(columns).not.toContain('secret');
    expect(columns).not.toContain('plaintext');
    expect(columns).toContain('ciphertext');
    expect(columns).toContain('wrapped_key');
    db.close();
  });
});
