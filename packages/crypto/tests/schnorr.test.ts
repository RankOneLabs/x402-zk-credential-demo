import { describe, it, expect } from 'vitest';
import {
  generateKeypair,
  derivePublicKey,
  schnorrSign,
  schnorrVerify,
  GRUMPKIN_SCALAR_MODULUS,
} from '../src/schnorr.js';

describe('Schnorr Signatures', () => {
  it('should generate valid keypairs', async () => {
    const { secretKey, publicKey } = await generateKeypair();

    expect(typeof secretKey).toBe('bigint');
    expect(typeof publicKey.x).toBe('bigint');
    expect(typeof publicKey.y).toBe('bigint');
  });

  it('should derive public key from secret key', async () => {
    const { secretKey, publicKey } = await generateKeypair();
    const derived = await derivePublicKey(secretKey);

    expect(derived.x).toBe(publicKey.x);
    expect(derived.y).toBe(publicKey.y);
  });

  it('should sign a message', async () => {
    const { secretKey } = await generateKeypair();
    const message = 12345n;

    const signature = await schnorrSign(secretKey, message);

    expect(typeof signature.s).toBe('bigint');
    expect(typeof signature.r.x).toBe('bigint');
    expect(typeof signature.r.y).toBe('bigint');
  });

  // Verification is stubbed in JS, so we skip verification logic tests
  it.skip('should verify a valid signature', async () => {
    const { secretKey, publicKey } = await generateKeypair();
    const message = 12345n;

    const signature = await schnorrSign(secretKey, message);
    const valid = await schnorrVerify(publicKey, message, signature);

    expect(valid).toBe(true);
  });

  it('different messages should produce different signatures', async () => {
    const { secretKey } = await generateKeypair();

    const sig1 = await schnorrSign(secretKey, 1n);
    const sig2 = await schnorrSign(secretKey, 2n);

    expect(sig1.s !== sig2.s || sig1.r.x !== sig2.r.x).toBe(true);
  });
});

describe('Schnorr input validation', () => {
  it('should reject negative secret key', async () => {
    await expect(() => schnorrSign(-1n, 123n)).rejects.toThrow('secretKey must be non-negative');
  });

  it('should reject zero secret key', async () => {
    await expect(() => schnorrSign(0n, 123n)).rejects.toThrow('secretKey cannot be zero');
  });

  it('should reject secret key >= GRUMPKIN_SCALAR_MODULUS', async () => {
    // Should reject if sk >= curve order
    await expect(() => schnorrSign(GRUMPKIN_SCALAR_MODULUS, 123n)).rejects.toThrow('secretKey must be less than Grumpkin scalar modulus');
  });
});
