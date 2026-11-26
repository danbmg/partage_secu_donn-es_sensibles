import {
  createRandomSalt,
  decryptText,
  deriveAuthHash,
  deriveEncryptionKey,
  encryptText,
  generateRsaKeyPair,
  importRsaPrivateKey,
} from './crypto/index.js';
import { apiRequest } from './http.js';

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

export async function registerAccount(email: string, masterPassword: string): Promise<string> {
  const salt = createRandomSalt();
  const authHash = await deriveAuthHash(masterPassword, salt);
  const keyPair = await generateRsaKeyPair();
  const encryptionKey = await deriveEncryptionKey(masterPassword, salt);
  const encryptedPrivateKey = await encryptText(keyPair.privateKey, encryptionKey);
  const result = await apiRequest<RegistrationResponse>('/api/register', {
    method: 'POST',
    body: { email, salt, authHash, publicKey: keyPair.publicKey, encryptedPrivateKey },
  });
  return result.userId;
}

export async function loginAccount(email: string, masterPassword: string): Promise<AuthenticatedSession> {
  const { salt } = await apiRequest<SaltResponse>(`/api/auth/salt?email=${encodeURIComponent(email)}`);
  const authHash = await deriveAuthHash(masterPassword, salt);
  const result = await apiRequest<LoginResponse>('/api/login', { method: 'POST', body: { email, authHash } });
  const encryptionKey = await deriveEncryptionKey(masterPassword, salt);
  const privateKeyBase64 = await decryptText(result.encryptedPrivateKey, encryptionKey);
  const privateKey = await importRsaPrivateKey(privateKeyBase64);
  return { token: result.token, userId: result.userId, publicKey: result.publicKey, privateKey };
}

// Asks the server to forget the session, so a copied token stops working too.
export async function logoutAccount(session: AuthenticatedSession): Promise<void> {
  await apiRequest<void>('/api/logout', { method: 'POST', token: session.token });
}
