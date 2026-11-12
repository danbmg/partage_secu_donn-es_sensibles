import { describe, expect, it } from 'vitest';
import {
  createRandomItemKey,
  createRandomSalt,
  decryptText,
  deriveAuthHash,
  deriveEncryptionKey,
  encryptText,
  generateRsaKeyPair,
  importAesKey,
  importRsaPrivateKey,
  unwrapItemKey,
  wrapItemKey,
} from './index.js';

describe('client cryptography', () => {
  it('derives a stable authentication value and encrypts/decrypts with AES-256-GCM', async () => {
    const salt = createRandomSalt();
    const key = await deriveEncryptionKey('correct horse battery staple', salt);
    const envelope = await encryptText('secret note', key);

    expect(await decryptText(envelope, key)).toBe('secret note');
    expect(await deriveAuthHash('correct horse battery staple', salt)).toBe(
      await deriveAuthHash('correct horse battery staple', salt),
    );
  }, 15_000);

  it('rejects decryption with a different key', async () => {
    const first = await importAesKey(await createRandomItemKey());
    const second = await importAesKey(await createRandomItemKey());
    const envelope = await encryptText('private', first);

    await expect(decryptText(envelope, second)).rejects.toThrow();
  });

  it('wraps an item key for a recipient public key and unwraps it client-side', async () => {
    const keys = await generateRsaKeyPair();
    const rawItemKey = await createRandomItemKey();
    const wrapped = await wrapItemKey(rawItemKey, keys.publicKey);
    const privateKey = await importRsaPrivateKey(keys.privateKey);

    expect(Array.from(await unwrapItemKey(wrapped, privateKey))).toEqual(Array.from(rawItemKey));
  }, 15_000);
});
