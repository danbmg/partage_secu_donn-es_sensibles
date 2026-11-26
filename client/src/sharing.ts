import type { AuthenticatedSession } from './auth.js';
import {
  createRandomItemKey,
  decryptText,
  encryptText,
  importAesKey,
  unwrapItemKey,
  wrapItemKey,
} from './crypto/index.js';
import { apiRequest } from './http.js';

interface SharedItem {
  id: string;
  ciphertext: string;
  wrappedKey: string;
}

export interface ItemAccess {
  userId: string;
  email: string;
  publicKey: string | null;
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

// Removing the recipient's wrapped key is not enough: they may have kept the item key.
// So the item is re-encrypted under a brand-new key, wrapped only for those who keep access.
export async function revokeVaultItemAccess(
  itemId: string,
  revokedUserId: string,
  session: AuthenticatedSession,
): Promise<void> {
  const path = `/api/items/${encodeURIComponent(itemId)}`;
  const item = await apiRequest<SharedItem>(path, { token: session.token });
  const accesses = await listItemAccess(itemId, session);
  if (!accesses.some((access) => access.userId === revokedUserId)) throw new Error('This user has no access to the item');

  const oldKey = await importAesKey(await unwrapItemKey(item.wrappedKey, session.privateKey));
  const plaintext = await decryptText(item.ciphertext, oldKey);
  const newRawKey = await createRandomItemKey();
  const ciphertext = await encryptText(plaintext, await importAesKey(newRawKey));

  const wrappedKeys = await Promise.all(
    accesses
      .filter((access) => access.userId !== revokedUserId)
      .map(async (access) => {
        // For myself, trust the key I hold rather than the copy the server returns.
        const publicKey = access.userId === session.userId ? session.publicKey : access.publicKey;
        if (!publicKey) throw new Error('Missing public key for a remaining recipient');
        return { userId: access.userId, wrappedKey: await wrapItemKey(newRawKey, publicKey) };
      }),
  );
  await apiRequest<void>(`${path}/shares/${encodeURIComponent(revokedUserId)}`, {
    method: 'DELETE',
    token: session.token,
    body: { ciphertext, wrappedKeys },
  });
}
