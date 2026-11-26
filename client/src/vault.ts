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

export interface VaultSecret {
  name: string;
  username: string;
  password: string;
  notes: string;
}

interface EncryptedItem {
  id: string;
  ownerId: string;
  ciphertext: string;
  wrappedKey: string;
  createdAt: string;
  updatedAt: string;
}

export interface VaultItem extends VaultSecret {
  id: string;
  ownerId: string;
  createdAt: string;
  updatedAt: string;
}

async function api<T>(path: string, session: AuthenticatedSession, init?: { method?: string; body?: unknown }): Promise<T> {
  return apiRequest<T>(path, { ...init, token: session.token });
}

async function decryptItem(item: EncryptedItem, session: AuthenticatedSession): Promise<VaultItem> {
  const rawItemKey = await unwrapItemKey(item.wrappedKey, session.privateKey);
  const key = await importAesKey(rawItemKey);
  const secret = JSON.parse(await decryptText(item.ciphertext, key)) as VaultSecret;
  return {
    ...secret,
    id: item.id,
    ownerId: item.ownerId,
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
  };
}

export async function createVaultItem(
  secret: VaultSecret,
  session: AuthenticatedSession,
): Promise<{ id: string }> {
  const rawItemKey = await createRandomItemKey();
  const itemKey = await importAesKey(rawItemKey);
  const ciphertext = await encryptText(JSON.stringify(secret), itemKey);
  const wrappedKey = await wrapItemKey(rawItemKey, session.publicKey);
  return api('/api/items', session, {
    method: 'POST',
    body: { ciphertext, wrappedKey },
  });
}

export async function readVaultItems(session: AuthenticatedSession): Promise<VaultItem[]> {
  const { items } = await api<{ items: EncryptedItem[] }>('/api/items', session);
  return Promise.all(items.map((item) => decryptItem(item, session)));
}

// Re-encrypts the new content with the item's existing key (fresh IV): everyone who
// already has access keeps it, nobody new gets it.
export async function updateVaultItem(
  id: string,
  secret: VaultSecret,
  session: AuthenticatedSession,
): Promise<void> {
  const path = `/api/items/${encodeURIComponent(id)}`;
  const existing = await api<EncryptedItem>(path, session);
  if (existing.ownerId !== session.userId) throw new Error('Only the owner can update this item');
  const key = await importAesKey(await unwrapItemKey(existing.wrappedKey, session.privateKey));
  const ciphertext = await encryptText(JSON.stringify(secret), key);
  await api(path, session, { method: 'PUT', body: { ciphertext } });
}

// The server checks ownership and deletes the item with every wrapped key (cascade).
export async function deleteVaultItem(id: string, session: AuthenticatedSession): Promise<void> {
  await api(`/api/items/${encodeURIComponent(id)}`, session, { method: 'DELETE' });
}
