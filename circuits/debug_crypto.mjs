// Debug script to verify cryptographic values match between TypeScript and Noir
import { Barretenberg, Fr } from '@aztec/bb.js';
import { poseidon5, poseidon7 } from 'poseidon-lite';

const bb = await Barretenberg.new({ threads: 1 });

// Test values from Prover.toml
const service_id = 1n;
const tier = 1n;
const max_presentations = 1000n;
const issued_at = 1706547800n;
const expires_at = 1800000000n;
const nullifier_seed = 12345n;
const blinding_factor = 67890n;

// Compute commitment
const commitment = await bb.pedersenCommit([new Fr(nullifier_seed), new Fr(blinding_factor)], 0);
const commitment_x = frToBigInt(commitment.x);
const commitment_y = frToBigInt(commitment.y);

console.log('=== Pedersen Commitment ===');
console.log('commitment_x:', commitment_x);
console.log('commitment_y:', commitment_y);

// Compute message hash (what gets signed)
const msg_hash = poseidon7([
    service_id,
    tier,
    max_presentations,
    issued_at,
    expires_at,
    commitment_x,
    commitment_y
]);

console.log('\n=== Message Hash (Poseidon7) ===');
console.log('msg_hash:', msg_hash);

// Now let's verify Schnorr signature
// Generate a keypair
const sk = 12345n;
const pk = await grumpkinScalarMulG(sk);
console.log('\n=== Keypair ===');
console.log('pk.x:', pk.x);
console.log('pk.y:', pk.y);

// Random nonce
const k = 67890n;
const R = await grumpkinScalarMulG(k);
console.log('\n=== Nonce Point R ===');
console.log('R.x:', R.x);
console.log('R.y:', R.y);

// Challenge e = H(R || pk || msg)
const e = poseidon5([R.x, R.y, pk.x, pk.y, msg_hash]);
console.log('\n=== Challenge e ===');
console.log('e:', e);
console.log('e (hex):', e.toString(16));

// s = k + e * sk
const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const s = (k + e * sk) % FIELD_MODULUS;
console.log('\n=== Signature s ===');
console.log('s:', s);

// Split into limbs
const LIMB_MASK = (1n << 128n) - 1n;
const s_lo = s & LIMB_MASK;
const s_hi = s >> 128n;
console.log('s_lo:', s_lo);
console.log('s_hi:', s_hi);

// Verify: s*G == R + e*pk
const sG = await grumpkinScalarMulG(s);
console.log('\n=== Verification ===');
console.log('s*G.x:', sG.x);
console.log('s*G.y:', sG.y);

// R + e*pk
// We need point addition which bb.js doesn't directly expose...
// But we can check if the expected equation holds

await bb.destroy();

// Helper functions
function frToBigInt(fr) {
    let result = 0n;
    for (const byte of fr.value) {
        result = (result << 8n) | BigInt(byte);
    }
    return result;
}

async function grumpkinScalarMulG(s) {
    const result = await bb.pedersenCommit([new Fr(BigInt(s)), new Fr(0n)], 0);
    return {
        x: frToBigInt(result.x),
        y: frToBigInt(result.y),
    };
}
