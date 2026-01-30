/**
 * Pedersen Commitment Implementation
 * 
 * Uses Barretenberg's pedersen_commitment to match Noir's std::hash::pedersen_commitment.
 * 
 * Commitment: C = secret * G0 + blinding * G1
 * Where G0, G1 are Barretenberg's default generators on Grumpkin.
 */

import { BarretenbergSync, Fr } from '@aztec/bb.js';
import type { Point, Commitment } from './types.js';
import { randomFieldElement, toField } from './utils.js';

/**
 * Generator index offset for Barretenberg's pedersen_commitment.
 * Using 0 selects the default generators (G0, G1, ...) from Barretenberg's
 * precomputed table. These match Noir's std::hash::pedersen_commitment.
 */
const PEDERSEN_GENERATOR_INDEX = 0;

// Lazy initialization of Barretenberg
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
 * Convert bigint to Fr (field element)
 */
function toFr(value: bigint): Fr {
  return new Fr(value);
}

/**
 * Convert Fr result to bigint
 */
function fromFr(fr: Fr): bigint {
  // Fr.value is a Uint8Array, convert to bigint
  let result = 0n;
  for (const byte of fr.value) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

/**
 * Create a Pedersen commitment to a secret value
 * 
 * Uses Barretenberg's pedersen_commitment which computes:
 * C = inputs[0] * G0 + inputs[1] * G1 + ...
 * 
 * For a hiding commitment, we pass [secret, blinding].
 * 
 * @param secret - The value to commit to
 * @param blinding - Optional blinding factor (random if not provided)
 * @returns Commitment with point and opening values
 */
export async function pedersenCommit(secret: bigint, blinding?: bigint): Promise<Commitment> {
  const blindingFactor = blinding ?? randomFieldElement();
  const api = await ensureBb();
  
  // Pedersen commit using Barretenberg's generators
  const inputs = [
    toFr(toField(secret)),
    toFr(toField(blindingFactor)),
  ];
  
  const result = api.pedersenCommit(inputs, PEDERSEN_GENERATOR_INDEX);

  return {
    point: {
      x: fromFr(result.x),
      y: fromFr(result.y),
    },
    secret: toField(secret),
    blinding: blindingFactor,
  };
}

/**
 * Synchronous version - requires bb to be initialized first
 */
export function pedersenCommitSync(secret: bigint, blinding?: bigint): Commitment {
  if (!bbInitialized) {
    throw new Error('Barretenberg not initialized. Call pedersenCommit() first or await initPedersen()');
  }
  
  const blindingFactor = blinding ?? randomFieldElement();
  
  const inputs = [
    toFr(toField(secret)),
    toFr(toField(blindingFactor)),
  ];
  
  const result = bb.pedersenCommit(inputs, PEDERSEN_GENERATOR_INDEX);

  return {
    point: {
      x: fromFr(result.x),
      y: fromFr(result.y),
    },
    secret: toField(secret),
    blinding: blindingFactor,
  };
}

/**
 * Initialize Barretenberg for synchronous operations
 */
export async function initPedersen(): Promise<void> {
  await ensureBb();
}

/**
 * Verify that a commitment opens to the given values
 */
export async function verifyCommitment(
  commitment: Point,
  secret: bigint,
  blinding: bigint
): Promise<boolean> {
  const expected = await pedersenCommit(secret, blinding);
  return expected.point.x === commitment.x && expected.point.y === commitment.y;
}
