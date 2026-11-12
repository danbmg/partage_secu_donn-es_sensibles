import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const SCRYPT_OPTIONS = { N: 32_768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const KEY_LENGTH = 64;

export function hashAuthenticationProof(proof: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(proof, salt, KEY_LENGTH, SCRYPT_OPTIONS);
  return `${salt.toString('base64')}:${hash.toString('base64')}`;
}

export function verifyAuthenticationProof(proof: string, encoded: string): boolean {
  const [saltText, expectedText] = encoded.split(':');
  if (!saltText || !expectedText) return false;
  const salt = Buffer.from(saltText, 'base64');
  const expected = Buffer.from(expectedText, 'base64');
  if (salt.length !== 16 || expected.length !== KEY_LENGTH) return false;
  const actual = scryptSync(proof, salt, KEY_LENGTH, SCRYPT_OPTIONS);
  return timingSafeEqual(actual, expected);
}
