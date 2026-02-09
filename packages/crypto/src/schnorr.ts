/**
 * Schnorr Signature Implementation using @aztec/bb.js (Grumpkin)
 * 
 * Sign: (R, s) where R = k*G, s = k + e * sk (mod Fq)
 * Verify: Not fully implemented in JS (requires arbitrary point arithmetic)
 * 
 * Uses BarretenbergSync (shared singleton with pedersen.ts) to avoid
 * spinning up a second WASM runtime.
 */

import { BarretenbergSync, Fr } from '@aztec/bb.js';
import type { Point, SchnorrSignature } from './types.js';
import { poseidonHash } from './poseidon.js';
import { randomFieldElement } from './utils.js';

// Grumpkin Scalar Field (BN254 Base Field)
// This is the order of the group (approx Fq) used for signature calculation s
export const GRUMPKIN_SCALAR_MODULUS = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

// Limit for Barretenberg Fr inputs
// const BN254_FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

let bbInitialized = false;
let bb: BarretenbergSync;

async function ensureBb(): Promise<BarretenbergSync> {
  if (!bbInitialized) {
    await BarretenbergSync.initSingleton();
    bb = BarretenbergSync.getSingleton();
    bbInitialized = true;
  }
  return bb;
}

/**
 * Generate a random Grumpkin scalar
 * Capped at BN254_FR_MODULUS to ensure compatibility with bb.js Fr inputs
 */
export function randomGrumpkinScalar(): bigint {
  // Use util which returns values < BN254_FR_MODULUS
  return randomFieldElement();
}

/**
 * Validate a scalar is in the valid range for Grumpkin scalar field [0, Fq)
 */
function validateScalar(value: bigint, name: string): void {
  if (value < 0n) {
    throw new Error(`${name} must be non-negative`);
  }
  if (value >= GRUMPKIN_SCALAR_MODULUS) {
    throw new Error(`${name} must be less than Grumpkin scalar modulus`);
  }
}

/**
 * Generate a keypair for Schnorr signing
 */
export async function generateKeypair(): Promise<{ secretKey: bigint; publicKey: Point }> {
  // Secret key must be in Fq (Grumpkin scalar field)
  // Our utils.randomFieldElement gives simple random bytes mod Fr (BN254 scalar).
  // We need random mod Fq.

  // Custom random generation for Fq
  const secretKey = randomGrumpkinScalar();

  const publicKey = await derivePublicKey(secretKey);

  return {
    secretKey,
    publicKey,
  };
}

/**
 * Derive public key from secret key
 * pk = sk * G
 */
export async function derivePublicKey(secretKey: bigint): Promise<Point> {
  validateScalar(secretKey, 'secretKey');
  const backend = await ensureBb();

  // pedersenCommit([s], 0) computes s * G + 0 * H = s * G
  const comm = backend.pedersenCommit([new Fr(secretKey), new Fr(0n)], 0);

  return {
    x: frToBigInt(comm.x),
    y: frToBigInt(comm.y),
  };
}

/**
 * Sign a message using Schnorr signature
 * 
 * @param secretKey - Signer's secret key
 * @param message - Message to sign (as field element, usually hash)
 * @returns Schnorr signature (R, s)
 */
export async function schnorrSign(secretKey: bigint, message: bigint): Promise<SchnorrSignature> {
  // Validate inputs
  validateScalar(secretKey, 'secretKey');
  // Message is likely in Fr (BN254 scalar), but it's just bits for the hash.
  // We don't strictly validate message < Fq, but usually it is from Poseidon (Fr).

  if (secretKey === 0n) {
    throw new Error('secretKey cannot be zero');
  }

  const backend = await ensureBb();

  // Generate random nonce k mod Fq
  const k = randomGrumpkinScalar();

  // R = k * G
  const kFr = new Fr(k);

  const commR = backend.pedersenCommit([kFr, new Fr(0n)], 0);

  const Rx = frToBigInt(commR.x);
  const Ry = frToBigInt(commR.y);

  // Verify on curve locally
  /*
  const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  const lhs = (Ry * Ry) % FIELD_MODULUS;
  const rhs = ((Rx * Rx * Rx) - 17n) % FIELD_MODULUS;
  const rhsPos = rhs < 0n ? rhs + FIELD_MODULUS : rhs;
  console.log('[Schnorr] R on curve:', lhs === rhsPos);
  */

  // Derive public key for hash
  // We can re-derive or expect it passed? Implementation signature is just (sk, m).
  // We must re-derive to be safe (or optimization: assume sk is valid)
  // Optimization: usually signing doesn't re-derive PK if not needed, but we ned it for 'e'.
  // If performance is an issue, we should change signature to take PK.
  const pk = await derivePublicKey(secretKey);

  // e = H(R || pk || m) using Poseidon (which uses standard BN254 Fr)
  // Note: Inputs to Poseidon are Fields (Fr). R.x, R.y, pk.x, pk.y are in Fr (Grumpkin coords).
  // message is in Fr.
  const e = poseidonHash([Rx, Ry, pk.x, pk.y, message]);

  // s = k + e * sk (mod Fq)
  // Calculate e * sk first. e is < Fr. sk is < Fq.
  // We do math in standard BigInt then reduce mod Fq.
  const s = (k + e * secretKey) % GRUMPKIN_SCALAR_MODULUS;

  return {
    r: { x: Rx, y: Ry },
    s,
  };
}

/**
 * Verify a Schnorr signature
 * 
 * NOTE: This is NOT implemented in TS/bb.js efficiently yet because specific point addition
 * is not exposed in the high-level bb.js API.
 * 
 * Returns true mostly as a placeholder or throws. 
 * Since this function is not critical for the server (which uses ZK proofs), we stub it.
 */
export async function schnorrVerify(
  publicKey: Point,
  message: bigint,
  signature: SchnorrSignature
): Promise<boolean> {
  // Cannot verify in JS without arbitrary point multiplication.
  // bb.js pedersenCommit only does scalars * generators.
  throw new Error("schnorrVerify is not implemented in JS. Verification must be performed via the Noir circuit.");
}

// Helper: Convert bb.js Fr to BigInt safely
function frToBigInt(fr: { toString: () => string }): bigint {
  // fr.toString() returns hex string "0x..." 
  // This handles any internal Montgomery representation automatically
  return BigInt(fr.toString());
}
