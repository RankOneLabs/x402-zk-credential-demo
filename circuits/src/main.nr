// x402 ZK Credential Circuit
// Proves: "I hold a valid credential for this service" while only revealing the credential's tier, expiry, and origin token publicly

mod pedersen;
mod schnorr;
mod utils;
mod test_generator;

use poseidon::poseidon::bn254;


// Main circuit entry point
fn main(
    // === Public inputs ===
    service_id: pub Field,
    current_time: pub Field,
    origin_id: pub Field,
    facilitator_pubkey_x: pub Field,
    facilitator_pubkey_y: pub Field,
    
    // === Private inputs: Credential ===
    cred_service_id: Field,
    cred_tier: Field,
    cred_identity_limit: Field,
    cred_expires_at: Field,
    cred_commitment_x: Field,
    cred_commitment_y: Field,
    
    // === Private inputs: Signature ===
    sig_r_x: Field,
    sig_r_y: Field,
    sig_s_lo: Field,  // Low 128 bits of s
    sig_s_hi: Field,  // High 128 bits of s
    
    // === Private inputs: User secrets ===
    nullifier_seed: Field,
    blinding_factor: Field,
    
    // === Private inputs: Presentation context ===
    identity_index: Field,
) -> pub (Field, Field, Field) {
    // Returns: (origin_token, tier, expires_at)
    
    // 1. Verify Pedersen commitment opens correctly
    //    C = nullifier_seed * G + blinding_factor * H
    let expected_commitment = pedersen::commit(nullifier_seed, blinding_factor);
    assert(expected_commitment.0 == cred_commitment_x, "Commitment x mismatch");
    assert(expected_commitment.1 == cred_commitment_y, "Commitment y mismatch");
    
    // 2. Verify credential is for this service
    assert(cred_service_id == service_id, "Service ID mismatch");
    
    // 3. Verify credential is not expired
    // Using field comparison - expires_at must be greater than or equal to current_time
    assert(utils::field_gte(cred_expires_at, current_time), "Credential expired");
    
    // 4. Verify identity index is within budget
    assert(utils::field_lt(identity_index, cred_identity_limit), "Identity index exceeds limit");
    
    // 5. Compute message hash for signature verification
    let msg = bn254::hash_6([cred_service_id, cred_tier, cred_identity_limit, cred_expires_at, cred_commitment_x, cred_commitment_y]);
    
    // 6. Verify Schnorr signature
    let sig_valid = schnorr::verify(
        facilitator_pubkey_x,
        facilitator_pubkey_y,
        msg,
        sig_r_x,
        sig_r_y,
        sig_s_lo,
        sig_s_hi
    );
    assert(sig_valid, "Invalid signature");
    
    // 7. Derive origin-bound token for rate limiting
    let origin_token = bn254::hash_3([nullifier_seed, origin_id, identity_index]);
    
    // 8. Return tier and expiry for access control
    (origin_token, cred_tier, cred_expires_at)
}

#[test]
fn test_valid_credential() {
    // TODO: Add test with valid credential
    // This will be populated once we have test vectors from TypeScript
}
