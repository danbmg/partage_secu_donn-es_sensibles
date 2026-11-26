import { describe, expect, it } from 'vitest';
import { fromBase32, toBase32 } from './encoding.js';
import {
  createRecoveryKey,
  deriveRecoveryAuthHash,
  deriveRecoveryEncryptionKey,
  parseRecoveryKey,
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

  it('encodes recovery keys in base32 and reads them back whatever the case or separators', async () => {
    const bytes = Uint8Array.from({ length: 20 }, (_, index) => index * 13);
    expect(Array.from(fromBase32(toBase32(bytes)))).toEqual(Array.from(bytes));
    expect(toBase32(new TextEncoder().encode('foobar'))).toBe('MZXW6YTBOI');

    const key = createRecoveryKey();
    expect(key).toMatch(/^([A-Z2-7]{4}-){7}[A-Z2-7]{4}$/);
    expect(parseRecoveryKey(key.toLowerCase().replaceAll('-', ' '))).toEqual(parseRecoveryKey(key));
    expect(() => parseRecoveryKey('ABCD-EFGH')).toThrow('Invalid recovery key');
    expect(() => parseRecoveryKey(key.replace(/^./, '0'))).toThrow('Invalid recovery key');
  });

  it('derives separate, stable proof and encryption key from a recovery key', async () => {
    const key = createRecoveryKey();
    expect(await deriveRecoveryAuthHash(key)).toBe(await deriveRecoveryAuthHash(key.toLowerCase()));
    expect(await deriveRecoveryAuthHash(key)).not.toBe(await deriveRecoveryAuthHash(createRecoveryKey()));

    const envelope = await encryptText('pkcs8 private key', await deriveRecoveryEncryptionKey(key));
    expect(await decryptText(envelope, await deriveRecoveryEncryptionKey(key))).toBe('pkcs8 private key');
    await expect(decryptText(envelope, await deriveRecoveryEncryptionKey(createRecoveryKey()))).rejects.toThrow();
  });
});
