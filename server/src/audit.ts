import type Database from 'better-sqlite3';

export const AUDIT_ACTIONS = ['login', 'logout', 'create', 'read', 'update', 'delete', 'share'] as const;
export type AuditAction = (typeof AUDIT_ACTIONS)[number];

interface AuditEvent {
  userId: string;
  action: AuditAction;
  itemId?: string | null;
  targetUserId?: string | null;
}

export function recordAudit(database: Database.Database, event: AuditEvent): void {
  database
    .prepare('INSERT INTO audit_log (user_id, item_id, target_user_id, action) VALUES (?, ?, ?, ?)')
    .run(event.userId, event.itemId ?? null, event.targetUserId ?? null, event.action);
}

export interface AuditEntry {
  id: number;
  action: AuditAction;
  itemId: string | null;
  actorId: string;
  actorEmail: string;
  targetEmail: string | null;
  createdAt: string;
}

// What a user may see: everything they did themselves, and everything anyone did
// on an item they own (reads by recipients, shares, revocations...).
export function auditEntriesFor(database: Database.Database, userId: string, limit = 100): AuditEntry[] {
  return database
    .prepare(
      `SELECT a.id, a.action, a.item_id AS itemId, a.user_id AS actorId, actor.email AS actorEmail,
              target.email AS targetEmail, a.created_at AS createdAt
       FROM audit_log a
       JOIN users actor ON actor.id = a.user_id
       LEFT JOIN users target ON target.id = a.target_user_id
       WHERE a.user_id = ? OR a.item_id IN (SELECT id FROM items WHERE owner_id = ?)
       ORDER BY a.id DESC
       LIMIT ?`,
    )
    .all(userId, userId, limit) as AuditEntry[];
}
