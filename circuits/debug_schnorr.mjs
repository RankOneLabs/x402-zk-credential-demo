#!/usr/bin/env node
// Debug Schnorr signature verification values

import { poseidon5, poseidon7 } from 'poseidon-lite';

// Values from Prover.toml
const sig_r_x = 8133452793716644955509559047757201813520010119628013008937662966120857463999n;
const sig_r_y = 7528125239746031681292216735743127669762404881969538308859115897051455027226n;
const issuer_pubkey_x = 15501790467540795402110192392062054730366404792129399502903287068856064701286n;
const issuer_pubkey_y = 2608562393050429104357697687950054842550626122572829625007967229129328431216n;
const sig_s_lo = 64938586282495032248553570892401416042n;
const sig_s_hi = 51590879005356149205322120668166304983n;

// Credential values
const cred_commitment_x = 1174064385289564629069614027811202315496463851600307037813143587535931871049n;
const cred_commitment_y = 17728503547603906361997519818252527060372219074479031690013921614517041679708n;
const cred_service_id = 1n;
const cred_tier = 1n;
const cred_max_presentations = 1000n;
const cred_issued_at = 1706547800n;
const cred_expires_at = 1800000000n;

console.log('=== Schnorr Debug ===\n');

// Reconstruct s from lo/hi
const s = sig_s_lo + (sig_s_hi << 128n);
console.log('s (reconstructed):', s);
console.log('s_lo:', sig_s_lo);
console.log('s_hi:', sig_s_hi);

// What the circuit computes for msg hash (hash_7)
const msg_noir = poseidon7([
    cred_service_id,
    cred_tier,
    cred_max_presentations,
    cred_issued_at,
    cred_expires_at,
    cred_commitment_x,
    cred_commitment_y
]);
console.log('\nCircuit msg_hash (hash_7):', msg_noir);

// What the YAML computes (check the order in YAML)
// Looking at YAML: [service_id, tier, max_presentations, issued_at, expires_at, commitment.x, commitment.y]
// Same order! But check if it's poseidon7 or something else

// The challenge e = H(R || pk || msg) using poseidon5 in both
const e = poseidon5([sig_r_x, sig_r_y, issuer_pubkey_x, issuer_pubkey_y, msg_noir]);
console.log('\nChallenge e:', e);

// Split e into lo/hi (this is what circuit does)
const LIMB_MASK = (1n << 128n) - 1n;
const e_lo = e & LIMB_MASK;
const e_hi = e >> 128n;
console.log('e_lo:', e_lo);
console.log('e_hi:', e_hi);

// Now let's verify the signature math
// s = k + e * sk (mod p)
// So: s * G = k * G + e * sk * G = R + e * pk
// We need to verify: s * G == R + e * pk

console.log('\n=== Signature check requires EC point operations ===');
console.log('Need to verify: s * G == R + e * pk');
console.log('R.x:', sig_r_x);
console.log('R.y:', sig_r_y);
console.log('pk.x:', issuer_pubkey_x);
console.log('pk.y:', issuer_pubkey_y);

console.log('\n=== CRITICAL: Check message hash matches ===');
console.log('The YAML needs to compute the SAME message hash as the circuit');
