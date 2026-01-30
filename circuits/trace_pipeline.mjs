#!/usr/bin/env node
// Trace through the YAML pipeline to see what values are computed

import { poseidon5, poseidon7 } from 'poseidon-lite';
import { Barretenberg, Fr } from '@aztec/bb.js';

const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Helper to convert Fr to bigint
function frToBigInt(fr) {
    let result = 0n;
    for (const byte of fr.value) {
        result = (result << 8n) | BigInt(byte);
    }
    return result;
}

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
    
    console.log('=== YAML Pipeline Trace ===\n');
    
    // Inputs (matching YAML)
    const service_id = 1n;
    const tier = 1n;
    const max_presentations = 1000n;
    const issued_at = 1706547800n;
    const expires_at = 1800000000n;
    const nullifier_seed = 12345n;
    const blinding_factor = 67890n;
    
    console.log('Inputs:');
    console.log('  service_id:', service_id);
    console.log('  tier:', tier);
    console.log('  max_presentations:', max_presentations);
    console.log('  issued_at:', issued_at);
    console.log('  expires_at:', expires_at);
    console.log('  nullifier_seed:', nullifier_seed);
    console.log('  blinding_factor:', blinding_factor);
    
    // Step 1: Pedersen commitment
    console.log('\n--- Step 1: pedersenCommit ---');
    const commitInputs = [new Fr(nullifier_seed), new Fr(blinding_factor)];
    const commitment = await bb.pedersenCommit(commitInputs, 0);
    const commitment_x = frToBigInt(commitment.x);
    const commitment_y = frToBigInt(commitment.y);
    console.log('  commitment.x:', commitment_x);
    console.log('  commitment.y:', commitment_y);
    
    // Step 2: Message hash (poseidon7)
    console.log('\n--- Step 2: poseidonHash (7 inputs) ---');
    const msg_inputs = [
        service_id,
        tier,
        max_presentations,
        issued_at,
        expires_at,
        commitment_x,
        commitment_y
    ];
    console.log('  inputs:', msg_inputs.map(x => x.toString()));
    const message_hash = poseidon7(msg_inputs);
    console.log('  message_hash:', message_hash);
    
    // Step 3: Sign with Schnorr
    console.log('\n--- Step 3: signSchnorrBn254 ---');
    const sk = randomField();
    console.log('  secret_key:', sk);
    
    // pk = sk * G
    const pkResult = await bb.pedersenCommit([new Fr(sk), new Fr(0n)], 0);
    const pk_x = frToBigInt(pkResult.x);
    const pk_y = frToBigInt(pkResult.y);
    console.log('  pk.x:', pk_x);
    console.log('  pk.y:', pk_y);
    
    // Random nonce k
    const k = randomField();
    console.log('  nonce k:', k);
    
    // R = k * G
    const rResult = await bb.pedersenCommit([new Fr(k), new Fr(0n)], 0);
    const r_x = frToBigInt(rResult.x);
    const r_y = frToBigInt(rResult.y);
    console.log('  R.x:', r_x);
    console.log('  R.y:', r_y);
    
    // Challenge e = H(R || pk || message_hash) with poseidon5
    console.log('\n--- Computing challenge e ---');
    const e_inputs = [r_x, r_y, pk_x, pk_y, message_hash];
    console.log('  e inputs (R.x, R.y, pk.x, pk.y, msg):', e_inputs.map(x => x.toString()));
    const e = poseidon5(e_inputs);
    console.log('  e:', e);
    
    // s = k + e * sk (mod FIELD_MODULUS)
    const s = (k + e * sk) % FIELD_MODULUS;
    console.log('  s = k + e * sk:', s);
    
    // Split s
    const LIMB_MASK = (1n << 128n) - 1n;
    const s_lo = s & LIMB_MASK;
    const s_hi = s >> 128n;
    console.log('  s_lo:', s_lo);
    console.log('  s_hi:', s_hi);
    
    // Now verify: what the circuit will compute
    console.log('\n=== Circuit Verification (what Noir computes) ===\n');
    
    // Circuit recomputes message hash
    console.log('--- Circuit Step 1: Verify commitment ---');
    console.log('  Expected (from pedersenCommit):', commitment_x, commitment_y);
    console.log('  Passed as cred_commitment_x/y: same values');
    
    console.log('\n--- Circuit Step 2: Compute msg hash (bn254::hash_7) ---');
    const circuit_msg = poseidon7([
        service_id,    // cred_service_id
        tier,          // cred_tier
        max_presentations,  // cred_max_presentations
        issued_at,     // cred_issued_at
        expires_at,    // cred_expires_at
        commitment_x,  // cred_commitment_x
        commitment_y   // cred_commitment_y
    ]);
    console.log('  circuit msg:', circuit_msg);
    console.log('  matches TypeScript msg_hash?', circuit_msg === message_hash);
    
    console.log('\n--- Circuit Step 3: Verify Schnorr ---');
    // Circuit computes e = H(R || pk || msg)
    const circuit_e = poseidon5([r_x, r_y, pk_x, pk_y, circuit_msg]);
    console.log('  circuit e:', circuit_e);
    console.log('  matches TypeScript e?', circuit_e === e);
    
    // Split circuit_e
    const circuit_e_lo = circuit_e & LIMB_MASK;
    const circuit_e_hi = circuit_e >> 128n;
    console.log('  circuit e_lo:', circuit_e_lo);
    console.log('  circuit e_hi:', circuit_e_hi);
    
    // The verification: s * G == R + e * pk
    console.log('\n--- Verification equation: s * G == R + e * pk ---');
    console.log('  LHS: s * G (need multi_scalar_mul)');
    console.log('  RHS: R + e * pk (need multi_scalar_mul)');
    console.log('  We can only compute s * G with pedersenCommit, not R + e * pk');
    
    // Let's at least compute s * G
    const lhsResult = await bb.pedersenCommit([new Fr(s), new Fr(0n)], 0);
    const lhs_x = frToBigInt(lhsResult.x);
    const lhs_y = frToBigInt(lhsResult.y);
    console.log('  s * G:', lhs_x, lhs_y);
    
    console.log('\n=== Summary ===');
    console.log('If TypeScript and Noir compute the same msg hash and e,');
    console.log('then the signature should verify.');
    console.log('The issue might be in limb splitting or modular arithmetic.');
    
    await bb.destroy();
    process.exit(0);
}

main().catch(e => {
    console.error(e);
    process.exit(1);
});
