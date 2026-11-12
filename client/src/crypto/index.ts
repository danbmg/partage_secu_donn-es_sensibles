import { concatBytes, fromBase64, toBase64 } from './encoding.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const KDF_ITERATIONS = 600_000;
const AES_IV_BYTES = 12;
const AES_KEY_BYTES = 32;

function bufferSource(bytes: Uint8Array): ArrayBuffer {
  return new Uint8Array(bytes).buffer as ArrayBuffer;
}

function cryptoApi(): Crypto {
  if (!globalThis.crypto?.subtle) throw new Error('Web Crypto API is not available');
  return globalThis.crypto;
}

function domainSalt(salt: Uint8Array, domain: string): Uint8Array {
  return concatBytes(salt, encoder.encode(`\0partage-securise\0${domain}`));
}

async function passwordBaseKey(password: string): Promise<CryptoKey> {
  return cryptoApi().subtle.importKey('raw', bufferSource(encoder.encode(password)), 'PBKDF2', false, ['deriveBits', 'deriveKey']);
}

export async function deriveEncryptionKey(password: string, saltBase64: string): Promise<CryptoKey> {
  const baseKey = await passwordBaseKey(password);
  return cryptoApi().subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: bufferSource(domainSalt(fromBase64(saltBase64), 'encryption')),
      iterations: KDF_ITERATIONS,
    },
    baseKey,
    { name: 'AES-GCM', length: AES_KEY_BYTES * 8 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function deriveAuthHash(password: string, saltBase64: string): Promise<string> {
  const baseKey = await passwordBaseKey(password);
  const bits = await cryptoApi().subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: bufferSource(domainSalt(fromBase64(saltBase64), 'authentication')),
      iterations: KDF_ITERATIONS,
    },
    baseKey,
    256,
  );
  return toBase64(new Uint8Array(bits));
}

export function createRandomSalt(): string {
  const bytes = cryptoApi().getRandomValues(new Uint8Array(16));
  return toBase64(bytes);
}

export async function encryptBytes(plaintext: Uint8Array, key: CryptoKey): Promise<string> {
  const iv = cryptoApi().getRandomValues(new Uint8Array(AES_IV_BYTES));
  const ciphertext = await cryptoApi().subtle.encrypt({ name: 'AES-GCM', iv: bufferSource(iv) }, key, bufferSource(plaintext));
  return JSON.stringify({ iv: toBase64(iv), ciphertext: toBase64(new Uint8Array(ciphertext)) });
}

export async function decryptBytes(envelope: string, key: CryptoKey): Promise<Uint8Array> {
  const parsed: unknown = JSON.parse(envelope);
  if (!isAesEnvelope(parsed)) throw new Error('Invalid encrypted payload');
  const plaintext = await cryptoApi().subtle.decrypt(
    { name: 'AES-GCM', iv: bufferSource(fromBase64(parsed.iv)) },
    key,
    bufferSource(fromBase64(parsed.ciphertext)),
  );
  return new Uint8Array(plaintext);
}

export async function encryptText(plaintext: string, key: CryptoKey): Promise<string> {
  return encryptBytes(encoder.encode(plaintext), key);
}

export async function decryptText(envelope: string, key: CryptoKey): Promise<string> {
  return decoder.decode(await decryptBytes(envelope, key));
}

export async function createRandomItemKey(): Promise<Uint8Array> {
  return cryptoApi().getRandomValues(new Uint8Array(AES_KEY_BYTES));
}

export async function importAesKey(rawKey: Uint8Array, extractable = false): Promise<CryptoKey> {
  if (rawKey.length !== AES_KEY_BYTES) throw new Error('AES-256 keys must contain 32 bytes');
  return cryptoApi().subtle.importKey('raw', bufferSource(rawKey), { name: 'AES-GCM' }, extractable, ['encrypt', 'decrypt']);
}

export interface SerializedRsaKeyPair {
  publicKey: string;
  privateKey: string;
}

export async function generateRsaKeyPair(): Promise<SerializedRsaKeyPair> {
  const pair = await cryptoApi().subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt'],
  );
  const publicDer = await cryptoApi().subtle.exportKey('spki', pair.publicKey);
  const privateDer = await cryptoApi().subtle.exportKey('pkcs8', pair.privateKey);
  return { publicKey: toBase64(new Uint8Array(publicDer)), privateKey: toBase64(new Uint8Array(privateDer)) };
}

export async function importRsaPublicKey(encoded: string): Promise<CryptoKey> {
  return cryptoApi().subtle.importKey('spki', bufferSource(fromBase64(encoded)), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
}

export async function importRsaPrivateKey(encoded: string): Promise<CryptoKey> {
  return cryptoApi().subtle.importKey('pkcs8', bufferSource(fromBase64(encoded)), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
}

export async function wrapItemKey(rawItemKey: Uint8Array, recipientPublicKey: string): Promise<string> {
  if (rawItemKey.length !== AES_KEY_BYTES) throw new Error('AES-256 keys must contain 32 bytes');
  const publicKey = await importRsaPublicKey(recipientPublicKey);
  const wrapped = await cryptoApi().subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, bufferSource(rawItemKey));
  return toBase64(new Uint8Array(wrapped));
}

export async function unwrapItemKey(wrappedItemKey: string, privateKey: CryptoKey): Promise<Uint8Array> {
  const raw = await cryptoApi().subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, bufferSource(fromBase64(wrappedItemKey)));
  return new Uint8Array(raw);
}

interface AesEnvelope {
  iv: string;
  ciphertext: string;
}

function isAesEnvelope(value: unknown): value is AesEnvelope {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return typeof candidate.iv === 'string' && typeof candidate.ciphertext === 'string';
}
