import {
  createRandomSalt,
  decryptText,
  deriveAuthHash,
  deriveEncryptionKey,
  encryptText,
  generateRsaKeyPair,
  importRsaPrivateKey,
} from './crypto/index.js';

interface SaltResponse {
  salt: string;
}

interface RegistrationResponse {
  userId: string;
}

interface LoginResponse {
  token: string;
  userId: string;
  publicKey: string;
  encryptedPrivateKey: string;
}

export interface AuthenticatedSession {
  token: string;
  userId: string;
  publicKey: string;
  privateKey: CryptoKey;
}

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  const body: unknown = await response.json();
  if (!response.ok) {
    const message =
      typeof body === 'object' && body !== null && 'error' in body && typeof body.error === 'string'
        ? body.error
        : 'Request failed';
    throw new Error(message);
  }
  return body as T;
}

export async function registerAccount(email: string, masterPassword: string): Promise<string> {
  const salt = createRandomSalt();
  const authHash = await deriveAuthHash(masterPassword, salt);
  const keyPair = await generateRsaKeyPair();
  const encryptionKey = await deriveEncryptionKey(masterPassword, salt);
  const encryptedPrivateKey = await encryptText(keyPair.privateKey, encryptionKey);
  const result = await requestJson<RegistrationResponse>('/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email,
      salt,
      authHash,
      publicKey: keyPair.publicKey,
      encryptedPrivateKey,
    }),
  });
  return result.userId;
}

export async function loginAccount(email: string, masterPassword: string): Promise<AuthenticatedSession> {
  const { salt } = await requestJson<SaltResponse>(`/api/auth/salt?email=${encodeURIComponent(email)}`);
  const authHash = await deriveAuthHash(masterPassword, salt);
  const result = await requestJson<LoginResponse>('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, authHash }),
  });
  const encryptionKey = await deriveEncryptionKey(masterPassword, salt);
  const privateKeyBase64 = await decryptText(result.encryptedPrivateKey, encryptionKey);
  const privateKey = await importRsaPrivateKey(privateKeyBase64);
  return { token: result.token, userId: result.userId, publicKey: result.publicKey, privateKey };
}
