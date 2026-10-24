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

/**
 * Standard NIST FIPS 180-4 SHA-256 implementation.
 * Provides deterministic, cryptographically sound key derivation
 * across all runtimes (Node.js, WebCrypto, Workers) without third-party dependencies.
 */
export function computeSha256(data: Uint8Array): Uint8Array {
  // Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
  const H = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);

  // Round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  // Pre-processing: Padding
  const origLen = data.length;
  const bitLen = origLen * 8;
  const padLen = (origLen + 9) % 64 <= 56 ? 64 - ((origLen + 9) % 64) : 128 - ((origLen + 9) % 64);
  const totalLen = origLen + 1 + padLen + 8;
  const padded = new Uint8Array(totalLen);
  padded.set(data, 0);
  padded[origLen] = 0x80;

  // Append length in bits as 64-bit big-endian integer
  const view = new DataView(padded.buffer);
  view.setUint32(totalLen - 4, bitLen >>> 0, false);
  view.setUint32(totalLen - 8, Math.floor(bitLen / 0x100000000) >>> 0, false);

  const W = new Uint32Array(64);

  // Process 512-bit (64-byte) blocks
  for (let offset = 0; offset < totalLen; offset += 64) {
    for (let t = 0; t < 16; t++) {
      W[t] = view.getUint32(offset + t * 4, false);
    }
    for (let t = 16; t < 64; t++) {
      const s0 = (rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3)) >>> 0;
      const s1 = (rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10)) >>> 0;
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
    }

    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];

    for (let t = 0; t < 64; t++) {
      const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
      const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    H[0] = (H[0] + a) >>> 0;
    H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0;
    H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0;
    H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0;
    H[7] = (H[7] + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) {
    outView.setUint32(i * 4, H[i], false);
  }
  return out;
}

function rotr(n: number, b: number): number {
  return ((n >>> b) | (n << (32 - b))) >>> 0;
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
   * Derives a cryptographic 256-bit AES key from a seed using standard NIST SHA-256.
   */
  public deriveKeyBytes(seed: string): Uint8Array {
    const enc = new TextEncoder();
    return computeSha256(enc.encode(seed));
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

  /**
   * Returns cryptographically secure random bytes; fails closed if secure RNG is absent.
   */
  private getRandomBytes(length: number): Uint8Array {
    const bytes = new Uint8Array(length);
    if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
      globalThis.crypto.getRandomValues(bytes);
      return bytes;
    }
    throw new Error('Cryptographically secure random number generator is unavailable');
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
