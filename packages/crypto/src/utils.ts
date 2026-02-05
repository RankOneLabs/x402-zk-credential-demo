/**
 * Utility functions for field element operations
 */

import { createHash } from 'node:crypto';

// BN254 scalar field modulus
export const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Convert a bigint to a field element (mod p)
 */
export function toField(value: bigint): bigint {
  const mod = value % FIELD_MODULUS;
  return mod < 0n ? mod + FIELD_MODULUS : mod;
}

/**
 * Convert a hex string to a bigint
 */
export function hexToBigInt(hex: string): bigint {
  if (hex.startsWith('0x') || hex.startsWith('0X')) {
    hex = hex.slice(2);
  }
  if (hex.length === 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error('Invalid hexadecimal string');
  }
  return BigInt('0x' + hex);
}

/**
 * Convert a bigint to a hex string
 */
export function bigIntToHex(value: bigint, padBytes = 32): string {
  const hex = value.toString(16);
  return '0x' + hex.padStart(padBytes * 2, '0');
}

/**
 * Generate a random field element with uniform distribution
 * 
 * Uses 512 bits of randomness to make modular bias negligible (< 2^-250).
 */
export function randomFieldElement(): bigint {
  const bytes = new Uint8Array(64);
  crypto.getRandomValues(bytes);
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value % FIELD_MODULUS;
}

/**
 * Convert a string to a field element
 * 
 * NOTE: This is NOT a cryptographic hash. It treats the string as a base-256
 * number with modular reduction. Only use for non-security-critical purposes
 * like converting server-controlled identifiers (e.g., URL pathnames) to
 * field elements. Do not use for user-controlled input in security contexts.
 */
export function stringToField(str: string): bigint {
  const hash = createHash('sha256').update(str).digest();
  const hex = hash.toString('hex');
  const val = BigInt('0x' + hex);
  return val % FIELD_MODULUS;
}

/**
 * Convert bytes to field element
 */
export function bytesToField(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return toField(value);
}

/**
 * Convert field element to bytes (32 bytes, big-endian)
 */
export function fieldToBytes(field: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let value = field;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}
