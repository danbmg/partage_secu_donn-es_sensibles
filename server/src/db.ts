import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import Database from 'better-sqlite3';

// Version 0 of the schema. Never edit it: existing databases already contain it.
// Every change goes into a new entry of `migrations` below.
export const baseSchema = `
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    kdf_salt TEXT NOT NULL,
    auth_hash TEXT NOT NULL,
    public_key TEXT,
    encrypted_private_key TEXT,
    recovery_encrypted_private_key TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  );
  CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ciphertext TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  );
  CREATE TABLE IF NOT EXISTS item_keys (
    item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_key TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (item_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    item_id TEXT REFERENCES items(id) ON DELETE SET NULL,
    action TEXT NOT NULL CHECK (action IN ('login', 'create', 'read', 'update', 'delete', 'share')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  );
  CREATE INDEX IF NOT EXISTS idx_items_owner ON items(owner_id);
  CREATE INDEX IF NOT EXISTS idx_item_keys_user ON item_keys(user_id);
  CREATE INDEX IF NOT EXISTS idx_audit_user_created ON audit_log(user_id, created_at);
`;

// Migration N brings the database from version N to version N + 1 (PRAGMA user_version).
const migrations: string[] = [
  // 1. Audit log: record who was targeted by a share, and stop listing the allowed actions
  //    in a CHECK constraint (SQLite cannot alter one without rebuilding the table).
  //    The list now lives in server/src/audit.ts, the only place that writes the log.
  `
  CREATE TABLE audit_log_next (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    item_id TEXT REFERENCES items(id) ON DELETE SET NULL,
    target_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 32),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  );
  INSERT INTO audit_log_next (id, user_id, item_id, action, created_at)
    SELECT id, user_id, item_id, action, created_at FROM audit_log;
  DROP TABLE audit_log;
  ALTER TABLE audit_log_next RENAME TO audit_log;
  CREATE INDEX idx_audit_user_created ON audit_log(user_id, created_at);
  CREATE INDEX idx_audit_item ON audit_log(item_id);
  `,
];

export const schemaVersion = migrations.length;

function migrate(database: Database.Database): void {
  const current = database.pragma('user_version', { simple: true }) as number;
  for (let version = current; version < migrations.length; version += 1) {
    const step = database.transaction(() => {
      database.exec(migrations[version] as string);
      database.pragma(`user_version = ${version + 1}`);
    });
    step();
  }
}

export function openDatabase(filename = process.env.DB_PATH ?? 'data/app.sqlite'): Database.Database {
  const path = filename === ':memory:' ? filename : resolve(filename);
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const database = new Database(path);
  database.pragma('foreign_keys = ON');
  database.exec(baseSchema);
  migrate(database);
  return database;
}
