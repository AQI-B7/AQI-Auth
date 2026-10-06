import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'crypto';

/**
 * AES-256-GCM helper used to encrypt sensitive third-party tokens
 * (OAuth access/refresh tokens) before they are persisted.
 *
 * Format: base64(iv[12] || authTag[16] || ciphertext)
 */
export class TokenCipher {
  private readonly key: Buffer;

  constructor(secret: string) {
    // Accept raw 32-byte hex/base64 keys, or derive a 32-byte key from an
    // arbitrary passphrase (e.g. reusing JWT secret in local/dev setups).
    if (/^[0-9a-f]{64}$/i.test(secret)) {
      this.key = Buffer.from(secret, 'hex');
    } else if (Buffer.from(secret, 'base64').length === 32) {
      this.key = Buffer.from(secret, 'base64');
    } else {
      this.key = createHash('sha256').update(secret).digest();
    }
  }

  encrypt(plaintext: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([iv, authTag, encrypted]).toString('base64');
  }

  decrypt(payload: string): string {
    const raw = Buffer.from(payload, 'base64');
    const iv = raw.subarray(0, 12);
    const authTag = raw.subarray(12, 28);
    const ciphertext = raw.subarray(28);
    const decipher = createDecipheriv('aes-256-gcm', this.key, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  }
}
