/**
 * Project Fortress — Secrets Management, Envelope Encryption & Key Rotation
 * @license Apache-2.0
 */

export interface EncryptedEnvelope {
  version: number;
  keyId: string;
  iv: string; // Base64
  ciphertext: string; // Base64
  tag: string; // Base64 auth tag
  createdAt: string;
}

export class SecretManager {
  private activeKeyId: string;
  private keyring: Map<string, Uint8Array> = new Map();

  constructor(initialKeyId = 'k-2026-q4', initialKeyHex?: string) {
    this.activeKeyId = initialKeyId;
    const keyBytes = initialKeyHex
      ? this.hexToBytes(initialKeyHex)
      : this.deriveKeyBytes('fortress-default-master-key-seed-32bytes!');
    this.keyring.set(initialKeyId, keyBytes);
  }

  /**
   * Rotates the active master key to a new key identifier.
   */
  public rotateKey(newKeyId: string, newKeySeed: string): void {
    const keyBytes = this.deriveKeyBytes(newKeySeed);
    this.keyring.set(newKeyId, keyBytes);
    this.activeKeyId = newKeyId;
  }

  /**
   * Envelope encrypts a secret string using AES-GCM (256-bit).
   */
  public async encryptSecret(plaintext: string): Promise<EncryptedEnvelope> {
    const keyBytes = this.keyring.get(this.activeKeyId);
    if (!keyBytes) {
      throw new Error(`Active key '${this.activeKeyId}' not found in keyring`);
    }

    const iv = this.getRandomBytes(12); // 96-bit IV recommended for AES-GCM
    const enc = new TextEncoder();
    const data = enc.encode(plaintext);

    if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
      const cryptoKey = await globalThis.crypto.subtle.importKey(
        'raw',
        keyBytes as unknown as BufferSource,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
      );

      const cipherBuffer = await globalThis.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv as unknown as BufferSource, tagLength: 128 },
        cryptoKey,
        data
      );

      const cipherBytes = new Uint8Array(cipherBuffer);
      // WebCrypto AES-GCM appends the 16-byte auth tag at the end
      const tag = cipherBytes.slice(cipherBytes.length - 16);
      const ciphertext = cipherBytes.slice(0, cipherBytes.length - 16);

      return {
        version: 1,
        keyId: this.activeKeyId,
        iv: this.bytesToBase64(iv),
        ciphertext: this.bytesToBase64(ciphertext),
        tag: this.bytesToBase64(tag),
        createdAt: new Date().toISOString(),
      };
    }

    // Node.js fallback
    const nodeCrypto = await import('node:crypto');
    const cipher = nodeCrypto.createCipheriv('aes-256-gcm', keyBytes, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
      version: 1,
      keyId: this.activeKeyId,
      iv: Buffer.from(iv).toString('base64'),
      ciphertext: encrypted.toString('base64'),
      tag: tag.toString('base64'),
      createdAt: new Date().toISOString(),
    };
  }

  /**
   * Decrypts an encrypted envelope using the matching key in the keyring.
   */
  public async decryptSecret(envelope: EncryptedEnvelope): Promise<string> {
    const keyBytes = this.keyring.get(envelope.keyId);
    if (!keyBytes) {
      throw new Error(`Key '${envelope.keyId}' needed for decryption is not in keyring`);
    }

    const iv = this.base64ToBytes(envelope.iv);
    const ciphertext = this.base64ToBytes(envelope.ciphertext);
    const tag = this.base64ToBytes(envelope.tag);

    if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
      const cryptoKey = await globalThis.crypto.subtle.importKey(
        'raw',
        keyBytes as unknown as BufferSource,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
      );

      // Concatenate ciphertext and tag for WebCrypto
      const combined = new Uint8Array(ciphertext.length + tag.length);
      combined.set(ciphertext, 0);
      combined.set(tag, ciphertext.length);

      const decryptedBuffer = await globalThis.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv as unknown as BufferSource, tagLength: 128 },
        cryptoKey,
        combined as unknown as BufferSource
      );

      return new TextDecoder().decode(decryptedBuffer);
    }

    // Node.js fallback
    const nodeCrypto = await import('node:crypto');
    const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', keyBytes, iv);
    decipher.setAuthTag(Buffer.from(tag));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(ciphertext)),
      decipher.final(),
    ]);

    return decrypted.toString('utf8');
  }

  /**
   * Zeroizes a buffer in memory to reduce window of exposure.
   */
  public zeroize(buffer: Uint8Array): void {
    buffer.fill(0);
  }

  private deriveKeyBytes(seed: string): Uint8Array {
    const enc = new TextEncoder();
    const bytes = enc.encode(seed);
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      out[i] = bytes[i % bytes.length] ^ (i * 31);
    }
    return out;
  }

  private getRandomBytes(length: number): Uint8Array {
    const bytes = new Uint8Array(length);
    if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
      globalThis.crypto.getRandomValues(bytes);
    } else {
      for (let i = 0; i < length; i++) {
        bytes[i] = Math.floor(Math.random() * 256);
      }
    }
    return bytes;
  }

  private bytesToBase64(bytes: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  private base64ToBytes(b64: string): Uint8Array {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  private hexToBytes(hex: string): Uint8Array {
    const clean = hex.replace(/[^0-9a-fA-F]/g, '');
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) {
      bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
    }
    return bytes;
  }
}

export const defaultSecretManager = new SecretManager();
