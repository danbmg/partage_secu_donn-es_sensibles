import type { AuthenticatedSession } from './auth.js';
import { unwrapItemKey, wrapItemKey } from './crypto/index.js';
import { apiRequest } from './http.js';

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

export async function shareVaultItem(
  itemId: string,
  recipientEmail: string,
  session: AuthenticatedSession,
): Promise<void> {
  const { publicKey } = await apiRequest<{ publicKey: string }>(
    `/api/users/${encodeURIComponent(recipientEmail)}/public-key`,
  );
  const item = await apiRequest<SharedItem>(`/api/items/${encodeURIComponent(itemId)}`, { token: session.token });
  const rawItemKey = await unwrapItemKey(item.wrappedKey, session.privateKey);
  const wrappedKey = await wrapItemKey(rawItemKey, publicKey);
  await apiRequest<{ sharedWithUserId: string }>(`/api/items/${encodeURIComponent(itemId)}/shares`, {
    method: 'POST',
    token: session.token,
    body: { email: recipientEmail, wrappedKey },
  });
}

export async function listItemAccess(itemId: string, session: AuthenticatedSession): Promise<ItemAccess[]> {
  const { users } = await apiRequest<{ users: ItemAccess[] }>(`/api/items/${encodeURIComponent(itemId)}/shares`, {
    token: session.token,
  });
  return users;
}
