import { afterEach, describe, expect, it, vi } from 'vitest';
import { describeAuditEntry, readAuditLog, visibleAuditEntries, type AuditEntry } from './audit.js';

afterEach(() => vi.unstubAllGlobals());

function entry(overrides: Partial<AuditEntry>): AuditEntry {
  return {
    id: 1,
    action: 'read',
    itemId: 'item-1',
    actorId: 'me',
    actorEmail: 'me@example.com',
    targetEmail: null,
    createdAt: '2026-11-26T10:00:00.000Z',
    ...overrides,
  };
}

describe('audit log in the browser', () => {
  it('fetches the log with the session token', async () => {
    const fetchMock = vi.fn(async () => Response.json({ entries: [entry({})] }));
    vi.stubGlobal('fetch', fetchMock);

    expect(await readAuditLog({ token: 'tok', userId: 'me', publicKey: '', privateKey: {} as CryptoKey })).toHaveLength(1);
    expect(fetchMock).toHaveBeenCalledWith('/api/audit', { headers: { Authorization: 'Bearer tok' } });
  });

  it('hides my own reads but keeps reads by other people', () => {
    const entries = [entry({ id: 1 }), entry({ id: 2, actorId: 'bob' }), entry({ id: 3, action: 'share' })];
    expect(visibleAuditEntries(entries, 'me').map(({ id }) => id)).toEqual([2, 3]);
  });

  it('names items with their decrypted name and falls back when the item is gone', () => {
    const names = new Map([['item-1', 'Wi-Fi']]);
    expect(describeAuditEntry(entry({ action: 'share', targetEmail: 'bob@example.com' }), 'me', names)).toEqual({
      label: 'Partage',
      detail: '« Wi-Fi » avec bob@example.com',
      actor: 'vous',
    });
    expect(describeAuditEntry(entry({ actorId: 'bob', actorEmail: 'bob@example.com', itemId: 'gone' }), 'me', names)).toEqual({
      label: 'Lecture',
      detail: 'élément inaccessible',
      actor: 'bob@example.com',
    });
    expect(describeAuditEntry(entry({ action: 'delete', itemId: null }), 'me', names).detail).toBe('élément supprimé');
    expect(describeAuditEntry(entry({ action: 'login', itemId: null }), 'me', names).detail).toBe('');
    expect(describeAuditEntry(entry({ action: 'logout', itemId: null }), 'me', names)).toEqual({ label: 'Déconnexion', detail: '', actor: 'vous' });
  });
});
