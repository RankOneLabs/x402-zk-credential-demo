/**
 * Poseidon Hash Implementation
 * 
 * SNARK-friendly hash function using native field arithmetic.
 * Must match Noir's built-in Poseidon exactly.
 */

import { poseidon1, poseidon2, poseidon3, poseidon4, poseidon5, poseidon6 } from 'poseidon-lite';

/**
 * Poseidon hash of arbitrary number of field elements
 * 
 * @param inputs - Array of field elements to hash
 * @returns Single field element hash
 */
export function poseidonHash(inputs: bigint[]): bigint {
  if (inputs.length === 0) {
    throw new Error('Poseidon hash requires at least one input');
  }

  // Use the appropriate arity function
  switch (inputs.length) {
    case 1:
      return poseidon1(inputs) as bigint;
    case 2:
      return poseidon2(inputs) as bigint;
    case 3:
      return poseidon3(inputs) as bigint;
    case 4:
      return poseidon4(inputs) as bigint;
    case 5:
      return poseidon5(inputs) as bigint;
    case 6:
      return poseidon6(inputs) as bigint;
    default:
      // For larger inputs, use sponge construction
      return poseidonSponge(inputs);
  }
}

/**
 * Poseidon hash for 3 inputs (matches Noir's hash_3)
 */
export function poseidonHash3(a: bigint, b: bigint, c: bigint): bigint {
  return poseidon3([a, b, c]) as bigint;
}

/**
 * Poseidon hash for 5 inputs (matches Noir's hash_5)
 */
export function poseidonHash5(a: bigint, b: bigint, c: bigint, d: bigint, e: bigint): bigint {
  return poseidon5([a, b, c, d, e]) as bigint;
}

/**
 * Poseidon hash for 7 inputs.
 * 
 * IMPLEMENTATION NOTE:
 * Uses a hierarchical chaining approach: hash2(hash4(a..d), hash3(e..g)).
 * 
 * WARNING: This is a BREAKING CHANGE from the previous sponge construction.
 * This specific chaining method was chosen to match the manual implementation
 * in the Noir circuit (`main.nr`), ensuring bit-for-bit compatibility across
 * the JS and Noir environments.
 * 
 * Logic:
 * h1 = hash_4(a, b, c, d)
 * h2 = hash_3(e, f, g)
 * result = hash_2(h1, h2)
 */
export function poseidonHash7(a: bigint, b: bigint, c: bigint, d: bigint, e: bigint, f: bigint, g: bigint): bigint {
  const h1 = poseidon4([a, b, c, d]) as bigint;
  const h2 = poseidon3([e, f, g]) as bigint;
  return poseidon2([h1, h2]) as bigint;
}

/**
 * Poseidon sponge for variable-length inputs (>6 elements)
 * 
 * Uses rate-1 sponge construction: absorb each input by hashing (state, input)
 * with Poseidon-2. This matches Noir's sponge construction for compatibility.
 * 
 * Performance note: O(n) Poseidon calls for n inputs. For hot paths with
 * known fixed-size inputs, prefer the direct poseidonHash with ≤6 elements.
 */
function poseidonSponge(inputs: bigint[]): bigint {
  let state = 0n;

  for (const input of inputs) {
    state = poseidon2([state, input]) as bigint;
  }

  return state;
}
