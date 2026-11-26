import type { AuthenticatedSession } from './auth.js';
import { apiRequest } from './http.js';

export type AuditAction =
  | 'login'
  | 'logout'
  | 'recover'
  | 'recovery-update'
  | 'rotate-keys'
  | 'create'
  | 'read'
  | 'update'
  | 'delete'
  | 'share'
  | 'revoke';

export interface AuditEntry {
  id: number;
  action: AuditAction;
  itemId: string | null;
  actorId: string;
  actorEmail: string;
  targetEmail: string | null;
  createdAt: string;
}

export interface AuditLine {
  label: string;
  detail: string;
  actor: string;
}

// Actions about the account itself: they never point to an item.
const ACCOUNT_ACTIONS: ReadonlySet<AuditAction> = new Set<AuditAction>([
  'login',
  'logout',
  'recover',
  'recovery-update',
  'rotate-keys',
]);

const ACTION_LABELS: Record<AuditAction, string> = {
  login: 'Connexion',
  logout: 'Déconnexion',
  recover: 'Récupération du compte',
  'recovery-update': 'Nouvelle clé de secours',
  'rotate-keys': 'Renouvellement des clés',
  create: 'Création',
  read: 'Lecture',
  update: 'Modification',
  delete: 'Suppression',
  share: 'Partage',
  revoke: 'Retrait d’accès',
};

export async function readAuditLog(session: AuthenticatedSession): Promise<AuditEntry[]> {
  const { entries } = await apiRequest<{ entries: AuditEntry[] }>('/api/audit', { token: session.token });
  return entries;
}

// The user's own reads are logged on every vault refresh: showing them would bury
// the entries that matter (someone else reading or sharing one of my secrets).
export function visibleAuditEntries(entries: AuditEntry[], currentUserId: string): AuditEntry[] {
  return entries.filter((entry) => !(entry.action === 'read' && entry.actorId === currentUserId));
}

// Item names are encrypted: the server only knows item ids, the browser maps them back.
export function describeAuditEntry(
  entry: AuditEntry,
  currentUserId: string,
  itemNames: ReadonlyMap<string, string>,
): AuditLine {
  const actor = entry.actorId === currentUserId ? 'vous' : entry.actorEmail;
  let detail = '';
  if (entry.itemId) {
    const name = itemNames.get(entry.itemId);
    detail = name ? `« ${name} »` : 'élément inaccessible';
  } else if (!ACCOUNT_ACTIONS.has(entry.action)) {
    detail = 'élément supprimé';
  }
  if (entry.targetEmail) detail += ` ${entry.action === 'revoke' ? 'pour' : 'avec'} ${entry.targetEmail}`;
  return { label: ACTION_LABELS[entry.action] ?? entry.action, detail: detail.trim(), actor };
}
