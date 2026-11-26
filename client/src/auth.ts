import {
  createRandomSalt,
  decryptText,
  deriveAuthHash,
  deriveEncryptionKey,
  encryptText,
  generateRsaKeyPair,
  importRsaPrivateKey,
  keyPairMatches,
} from './crypto/index.js';
import { apiRequest } from './http.js';
import { createRecoveryMaterial } from './recovery.js';

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
  hasRecoveryKey: boolean;
}

export interface AuthenticatedSession {
  token: string;
  userId: string;
  publicKey: string;
  privateKey: CryptoKey;
  // Kept to re-check the master password before sensitive operations;
  // the private key copy is the encrypted one, never the plaintext.
  salt: string;
  encryptedPrivateKey: string;
  hasRecoveryKey: boolean;
}

export interface Registration {
  userId: string;
  recoveryKey: string;
}

export async function registerAccount(email: string, masterPassword: string): Promise<Registration> {
  const salt = createRandomSalt();
  const authHash = await deriveAuthHash(masterPassword, salt);
  const keyPair = await generateRsaKeyPair();
  const encryptionKey = await deriveEncryptionKey(masterPassword, salt);
  const encryptedPrivateKey = await encryptText(keyPair.privateKey, encryptionKey);
  const recovery = await createRecoveryMaterial(keyPair.privateKey);
  const result = await apiRequest<RegistrationResponse>('/api/register', {
    method: 'POST',
    body: {
      email,
      salt,
      authHash,
      publicKey: keyPair.publicKey,
      encryptedPrivateKey,
      recoveryAuthHash: recovery.recoveryAuthHash,
      recoveryEncryptedPrivateKey: recovery.recoveryEncryptedPrivateKey,
    },
  });
  return { userId: result.userId, recoveryKey: recovery.recoveryKey };
}

export async function loginAccount(email: string, masterPassword: string): Promise<AuthenticatedSession> {
  const { salt } = await apiRequest<SaltResponse>(`/api/auth/salt?email=${encodeURIComponent(email)}`);
  const authHash = await deriveAuthHash(masterPassword, salt);
  const result = await apiRequest<LoginResponse>('/api/login', { method: 'POST', body: { email, authHash } });
  const encryptionKey = await deriveEncryptionKey(masterPassword, salt);
  const privateKeyBase64 = await decryptText(result.encryptedPrivateKey, encryptionKey);
  const privateKey = await importRsaPrivateKey(privateKeyBase64);
  if (!(await keyPairMatches(result.publicKey, privateKey))) throw new Error('Public key does not match private key');
  return {
    token: result.token,
    userId: result.userId,
    publicKey: result.publicKey,
    privateKey,
    salt,
    encryptedPrivateKey: result.encryptedPrivateKey,
    hasRecoveryKey: result.hasRecoveryKey,
  };
}

// Asks the server to forget the session, so a copied token stops working too.
export async function logoutAccount(session: AuthenticatedSession): Promise<void> {
  await apiRequest<void>('/api/logout', { method: 'POST', token: session.token });
}
