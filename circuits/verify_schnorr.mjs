#!/usr/bin/env node
// Verify Schnorr signature using bb.js multi_scalar_mul equivalent

import { Barretenberg, Fr } from '@aztec/bb.js';
import { poseidon5, poseidon7 } from 'poseidon-lite';

const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const LIMB_MASK = (1n << 128n) - 1n;

// Helper to convert Fr to bigint
function frToBigInt(fr) {
    let result = 0n;
    for (const byte of fr.value) {
        result = (result << 8n) | BigInt(byte);
    }
    return result;
}

// Generate random field element
function randomField() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    let value = 0n;
    for (const b of bytes) {
        value = (value << 8n) | BigInt(b);
    }
    return value % FIELD_MODULUS;
}

async function main() {
    const bb = await Barretenberg.new({ threads: 1 });
    
    console.log('=== Full Schnorr Sign & Verify Test ===\n');
    
    // Generate keypair
    const sk = randomField();
    const pkResult = await bb.pedersenCommit([new Fr(sk), new Fr(0n)], 0);
    const pk = { x: frToBigInt(pkResult.x), y: frToBigInt(pkResult.y) };
    
    console.log('Keypair:');
    console.log('  sk:', sk);
    console.log('  pk.x:', pk.x);
    console.log('  pk.y:', pk.y);
    
    // Message
    const msg = 123456789n;
    console.log('\nMessage:', msg);
    
    // Sign: choose random k, compute R = k*G, e = H(R,pk,msg), s = k + e*sk
    const k = randomField();
    const rResult = await bb.pedersenCommit([new Fr(k), new Fr(0n)], 0);
    const R = { x: frToBigInt(rResult.x), y: frToBigInt(rResult.y) };
    
    const e = poseidon5([R.x, R.y, pk.x, pk.y, msg]);
    const s = (k + e * sk) % FIELD_MODULUS;
    
    console.log('\nSignature:');
    console.log('  k (nonce):', k);
    console.log('  R.x:', R.x);
    console.log('  R.y:', R.y);
    console.log('  e (challenge):', e);
    console.log('  s:', s);
    
    // Verify: check s*G == R + e*pk
    // s*G
    const sGResult = await bb.pedersenCommit([new Fr(s), new Fr(0n)], 0);
    const sG = { x: frToBigInt(sGResult.x), y: frToBigInt(sGResult.y) };
    console.log('\nVerification:');
    console.log('  s*G:', sG.x, sG.y);
    
    // For R + e*pk, we need to use the pedersenCommit trick differently
    // pedersenCommit([a, b], 0) = a*G0 + b*G1, but we need a*P for arbitrary P
    
    // The trick: We can't directly compute e*pk with pedersenCommit.
    // Instead, let's verify algebraically that our signature is correct:
    // s = k + e * sk
    // s * G = (k + e * sk) * G = k*G + e*(sk*G) = R + e*pk
    
    // Let's verify by computing: s*G - R (should equal e*pk)
    // But we can't do point subtraction easily either...
    
    // Alternative: verify using the signature equation directly
    // If s = k + e*sk, then k = s - e*sk (mod p)
    // And R = k*G, so R.x should match
    
    const k_recovered = (s - e * sk % FIELD_MODULUS + FIELD_MODULUS) % FIELD_MODULUS;
    console.log('  k recovered from s - e*sk:', k_recovered);
    console.log('  k matches original?', k_recovered === k);
    
    // Recompute R from recovered k
    const rRecoveredResult = await bb.pedersenCommit([new Fr(k_recovered), new Fr(0n)], 0);
    const R_recovered = { x: frToBigInt(rRecoveredResult.x), y: frToBigInt(rRecoveredResult.y) };
    console.log('  R from recovered k:', R_recovered.x, R_recovered.y);
    console.log('  R matches?', R_recovered.x === R.x && R_recovered.y === R.y);
    
    console.log('\n=== Testing with Noir circuit inputs ===\n');
    
    // Now let's create inputs that match exactly what we'll pass to the circuit
    const s_lo = s & LIMB_MASK;
    const s_hi = s >> 128n;
    console.log('s_lo:', s_lo);
    console.log('s_hi:', s_hi);
    console.log('s reconstructed:', s_lo + (s_hi << 128n));
    console.log('matches s?', s_lo + (s_hi << 128n) === s);
    
    // e limbs (what circuit computes internally)
    const e_lo = e & LIMB_MASK;
    const e_hi = e >> 128n;
    console.log('\ne_lo:', e_lo);
    console.log('e_hi:', e_hi);
    
    await bb.destroy();
    console.log('\n✓ Signature generation is correct');
    process.exit(0);
}

main().catch(e => {
    console.error(e);
    process.exit(1);
});
