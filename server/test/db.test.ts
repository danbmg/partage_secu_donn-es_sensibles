import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { describe, expect, it } from 'vitest';
import { baseSchema, openDatabase, schemaVersion } from '../src/db.js';

describe('SQLite schema', () => {
  it('creates the required tables and relationships on initialization', () => {
    const db = openDatabase(':memory:');
    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
      .all()
      .map((row) => (row as { name: string }).name);

    expect(tables).toEqual(['audit_log', 'item_keys', 'items', 'sessions', 'sqlite_sequence', 'users']);
    expect(db.pragma('foreign_keys', { simple: true })).toBe(1);
    expect(db.pragma('user_version', { simple: true })).toBe(schemaVersion);
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

  it('migrates a database created with the first schema without losing its rows', () => {
    const directory = mkdtempSync(join(tmpdir(), 'vault-db-'));
    const path = join(directory, 'app.sqlite');
    try {
      const legacy = new Database(path);
      legacy.exec(baseSchema);
      legacy.prepare('INSERT INTO users (id, email, kdf_salt, auth_hash) VALUES (?, ?, ?, ?)').run('u1', 'a@example.com', 'salt', 'hash');
      legacy.prepare("INSERT INTO audit_log (user_id, action) VALUES ('u1', 'login')").run();
      legacy.close();

      const migrated = openDatabase(path);
      expect(migrated.pragma('user_version', { simple: true })).toBe(schemaVersion);
      expect(migrated.prepare('SELECT user_id, action FROM audit_log').all()).toEqual([{ user_id: 'u1', action: 'login' }]);
      expect(migrated.prepare('SELECT email FROM users').all()).toEqual([{ email: 'a@example.com' }]);
      migrated.close();

      // Opening again is a no-op: migrations run once.
      const reopened = openDatabase(path);
      expect(reopened.pragma('user_version', { simple: true })).toBe(schemaVersion);
      reopened.close();
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
