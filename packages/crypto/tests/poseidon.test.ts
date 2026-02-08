import { describe, it, expect } from 'vitest';
import {
  poseidonHash,
  poseidonHash3,
  poseidonHash5,
  poseidonHash6,
} from '../src/poseidon.js';

describe('Poseidon Hash', () => {
  it('should hash single element', () => {
    const result = poseidonHash([1n]);
    expect(typeof result).toBe('bigint');
    expect(result > 0n).toBe(true);
  });
  
  it('should hash two elements', () => {
    const result = poseidonHash([1n, 2n]);
    expect(typeof result).toBe('bigint');
  });
  
  it('should hash three elements', () => {
    const result = poseidonHash3(1n, 2n, 3n);
    expect(typeof result).toBe('bigint');
  });
  
  it('should hash five elements', () => {
    const result = poseidonHash5(1n, 2n, 3n, 4n, 5n);
    expect(typeof result).toBe('bigint');
  });
  
  it('should hash six elements', () => {
    const result = poseidonHash6(1n, 2n, 3n, 4n, 5n, 6n);
    expect(typeof result).toBe('bigint');
  });
  
  it('should be deterministic', () => {
    const inputs = [1n, 2n, 3n];
    const h1 = poseidonHash(inputs);
    const h2 = poseidonHash(inputs);
    expect(h1).toBe(h2);
  });
  
  it('different inputs should produce different hashes', () => {
    const h1 = poseidonHash([1n, 2n]);
    const h2 = poseidonHash([1n, 3n]);
    expect(h1).not.toBe(h2);
  });
  
  it('should handle large field elements', () => {
    const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const large = FIELD_MODULUS; // FIELD_MODULUS - 1 + 1
    const reduced = large % FIELD_MODULUS;
    expect(reduced).toBe(0n);
    const result = poseidonHash([reduced]);
    expect(typeof result).toBe('bigint');
  });
  
  it('should throw error for empty array', () => {
    expect(() => poseidonHash([])).toThrow('Poseidon hash requires at least one input');
  });

  it('should match circomlibjs/poseidon-lite reference vector', () => {
    // Reference test vector from poseidon-lite / circomlibjs
    // hash([1, 2]) on BN254 scalar field
    // This value is the canonical reference used across ZK ecosystems
    const result = poseidonHash([1n, 2n]);
    expect(result.toString()).toBe(
      '7853200120776062878684798364095072458815029376092732009249414926327459813530'
    );
  });

  it('should match poseidon-lite reference for hash([0])', () => {
    // Poseidon hash of [0] using poseidon-lite / circomlibjs parameters
    const result = poseidonHash([0n]);
    expect(result.toString()).toBe(
      '19014214495641488759237505126948346942972912379615652741039992445865937985820'
    );
  });
});
