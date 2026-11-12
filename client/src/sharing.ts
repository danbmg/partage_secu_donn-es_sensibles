import type { AuthenticatedSession } from './auth.js';
import { unwrapItemKey, wrapItemKey } from './crypto/index.js';

interface SharedItem {
  id: string;
  ciphertext: string;
  wrappedKey: string;
}

export interface ItemAccess {
  userId: string;
  email: string;
  sharedAt: string;
}

async function parseResponse<T>(response: Response): Promise<T> {
  const body: unknown = response.status === 204 ? undefined : await response.json();
  if (!response.ok) {
    const message =
      typeof body === 'object' && body !== null && 'error' in body && typeof body.error === 'string'
        ? body.error
        : 'Request failed';
    throw new Error(message);
  }
  return body as T;
}

export async function shareVaultItem(
  itemId: string,
  recipientEmail: string,
  session: AuthenticatedSession,
): Promise<void> {
  const keyResponse = await fetch(`/api/users/${encodeURIComponent(recipientEmail)}/public-key`);
  const { publicKey } = await parseResponse<{ publicKey: string }>(keyResponse);
  const itemResponse = await fetch(`/api/items/${encodeURIComponent(itemId)}`, {
    headers: { Authorization: `Bearer ${session.token}` },
  });
  const item = await parseResponse<SharedItem>(itemResponse);
  const rawItemKey = await unwrapItemKey(item.wrappedKey, session.privateKey);
  const wrappedKey = await wrapItemKey(rawItemKey, publicKey);
  const shareResponse = await fetch(`/api/items/${encodeURIComponent(itemId)}/shares`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${session.token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: recipientEmail, wrappedKey }),
  });
  await parseResponse<{ sharedWithUserId: string }>(shareResponse);
}

export async function listItemAccess(itemId: string, session: AuthenticatedSession): Promise<ItemAccess[]> {
  const response = await fetch(`/api/items/${encodeURIComponent(itemId)}/shares`, {
    headers: { Authorization: `Bearer ${session.token}` },
  });
  const { users } = await parseResponse<{ users: ItemAccess[] }>(response);
  return users;
}
