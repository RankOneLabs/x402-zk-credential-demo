/**
 * Utility functions for field element operations
 */

import { createHash } from 'node:crypto';
import type { Point } from './types.js';

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
 * Convert a string to a field element using SHA-256
 * 
 * Uses cryptographic hashing (SHA-256) to map arbitrary strings to field elements.
 * The hash output is interpreted as a big-endian integer and reduced modulo the
 * BN254 scalar field order.
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

/**
 * Convert bytes to Base64URL string (no padding)
 */
export function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/**
 * Convert Base64URL string to bytes
 */
export function fromBase64Url(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, 'base64url'));
}

/**
 * Convert Point to bytes (uncompressed: 0x04 || x || y)
 */
export function pointToBytes(point: Point): Uint8Array {
  const xBytes = fieldToBytes(point.x);
  const yBytes = fieldToBytes(point.y);
  const result = new Uint8Array(1 + 32 + 32);
  result[0] = 0x04;
  result.set(xBytes, 1);
  result.set(yBytes, 33);
  return result;
}

/**
 * Convert bytes to Point (uncompressed: 0x04 || x || y)
 */
export function bytesToPoint(bytes: Uint8Array): Point {
  if (bytes.length !== 65 || bytes[0] !== 0x04) {
    throw new Error('Invalid point encoding: expected 65 bytes starting with 0x04');
  }
  const x = bytesToField(bytes.slice(1, 33));
  const y = bytesToField(bytes.slice(33, 65));
  return { x, y };
}
