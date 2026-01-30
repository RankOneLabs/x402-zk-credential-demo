/**
 * Schnorr Signature Implementation
 * 
 * Sign: (R, s) where R = k*G, s = k + H(R || pk || m) * sk
 * Verify: s*G == R + H(R || pk || m) * pk
 * 
 * Using BN254 G1 to match Noir circuit.
 */

import { bn254 } from '@noble/curves/bn254';
import type { Point, SchnorrSignature } from './types.js';
import { poseidonHash } from './poseidon.js';
import { randomFieldElement, toField, FIELD_MODULUS } from './utils.js';

const G1 = bn254.G1.ProjectivePoint;
const G = G1.BASE;

/**
 * Validate a scalar is in valid range [0, FIELD_MODULUS)
 */
function validateScalar(value: bigint, name: string): void {
  if (value < 0n) {
    throw new Error(`${name} must be non-negative`);
  }
  if (value >= FIELD_MODULUS) {
    throw new Error(`${name} must be less than field modulus`);
  }
}

/**
 * Validate a point is on the curve and not the identity
 */
function validatePoint(point: Point, name: string): void {
  if (point.x < 0n || point.y < 0n) {
    throw new Error(`${name} coordinates must be non-negative`);
  }
  if (point.x === 0n && point.y === 0n) {
    throw new Error(`${name} cannot be the point at infinity`);
  }
  try {
    // This throws if point is not on curve
    G1.fromAffine({ x: point.x, y: point.y });
  } catch {
    throw new Error(`${name} is not a valid point on the curve`);
  }
}

/**
 * Generate a keypair for Schnorr signing
 */
export function generateKeypair(): { secretKey: bigint; publicKey: Point } {
  const secretKey = randomFieldElement();
  const pk = G.multiply(secretKey).toAffine();
  
  return {
    secretKey,
    publicKey: { x: pk.x, y: pk.y },
  };
}

/**
 * Derive public key from secret key
 */
export function derivePublicKey(secretKey: bigint): Point {
  const pk = G.multiply(toField(secretKey)).toAffine();
  return { x: pk.x, y: pk.y };
}

/**
 * Sign a message using Schnorr signature
 * 
 * @param secretKey - Signer's secret key
 * @param message - Message to sign (as field element)
 * @returns Schnorr signature (R, s)
 */
export function schnorrSign(secretKey: bigint, message: bigint): SchnorrSignature {
  // Validate inputs
  validateScalar(secretKey, 'secretKey');
  validateScalar(message, 'message');
  
  if (secretKey === 0n) {
    throw new Error('secretKey cannot be zero');
  }

  // Generate random nonce
  const k = randomFieldElement();
  
  // R = k * G
  const R = G.multiply(k).toAffine();
  
  // Derive public key
  const pk = derivePublicKey(secretKey);
  
  // e = H(R || pk || m) using Poseidon
  const e = poseidonHash([R.x, R.y, pk.x, pk.y, message]);
  
  // s = k + e * sk (mod field)
  const s = toField(k + e * toField(secretKey));
  
  return {
    r: { x: R.x, y: R.y },
    s,
  };
}

/**
 * Verify a Schnorr signature
 * 
 * @param publicKey - Signer's public key
 * @param message - Message that was signed
 * @param signature - Signature to verify
 * @returns true if signature is valid
 */
export function schnorrVerify(
  publicKey: Point,
  message: bigint,
  signature: SchnorrSignature
): boolean {
  // Validate inputs
  validatePoint(publicKey, 'publicKey');
  validatePoint(signature.r, 'signature.r');
  validateScalar(message, 'message');
  validateScalar(signature.s, 'signature.s');

  // e = H(R || pk || m)
  const e = poseidonHash([
    signature.r.x,
    signature.r.y,
    publicKey.x,
    publicKey.y,
    message,
  ]);
  
  // LHS = s * G
  const lhs = G.multiply(signature.s).toAffine();
  
  // RHS = R + e * pk
  const R = G1.fromAffine({ x: signature.r.x, y: signature.r.y });
  const pk = G1.fromAffine({ x: publicKey.x, y: publicKey.y });
  const ePk = pk.multiply(e);
  const rhs = R.add(ePk).toAffine();
  
  return lhs.x === rhs.x && lhs.y === rhs.y;
}
