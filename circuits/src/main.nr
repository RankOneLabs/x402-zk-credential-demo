// x402 ZK Credential Circuit
// Proves: "I hold a valid credential for this service" while only revealing the credential's tier and origin token publicly

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
    issuer_pubkey_x: pub Field,
    issuer_pubkey_y: pub Field,
    
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
) -> pub (Field, Field) {
    // Returns: (origin_token, tier)
    
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
        issuer_pubkey_x,
        issuer_pubkey_y,
        msg,
        sig_r_x,
        sig_r_y,
        sig_s_lo,
        sig_s_hi
    );
    assert(sig_valid, "Invalid signature");
    
    // 7. Derive origin-bound token for rate limiting
    let origin_token = bn254::hash_3([nullifier_seed, origin_id, identity_index]);
    
    // 8. Return tier for access control (expiry enforced by assertion above)
    (origin_token, cred_tier)
}

#[test]
fn test_valid_credential() {
    // TODO: Add test with valid credential
    // This will be populated once we have test vectors from TypeScript
}

#[test(should_fail_with = "Commitment x mismatch")]
fn test_reject_wrong_commitment() {
    let nullifier_seed: Field = 12345;
    let blinding_factor: Field = 67890;
    let (cx, _cy) = pedersen::commit(nullifier_seed, blinding_factor);

    let _ = main(
        1, 100, 1, 0, 0,
        1, 1, 1000, 200,
        cx + 1, 999,
        0, 0, 0, 0,
        nullifier_seed, blinding_factor,
        0,
    );
}

#[test(should_fail_with = "Service ID mismatch")]
fn test_reject_service_id_mismatch() {
    let nullifier_seed: Field = 12345;
    let blinding_factor: Field = 67890;
    let (cx, cy) = pedersen::commit(nullifier_seed, blinding_factor);

    let _ = main(
        1, 100, 1, 0, 0,
        2, 1, 1000, 200,
        cx, cy,
        0, 0, 0, 0,
        nullifier_seed, blinding_factor,
        0,
    );
}

#[test(should_fail_with = "Credential expired")]
fn test_reject_expired_credential() {
    let nullifier_seed: Field = 12345;
    let blinding_factor: Field = 67890;
    let (cx, cy) = pedersen::commit(nullifier_seed, blinding_factor);

    let _ = main(
        1, 200, 1, 0, 0,
        1, 1, 1000, 100,
        cx, cy,
        0, 0, 0, 0,
        nullifier_seed, blinding_factor,
        0,
    );
}

#[test(should_fail_with = "Identity index exceeds limit")]
fn test_reject_identity_index_exceeds_limit() {
    let nullifier_seed: Field = 12345;
    let blinding_factor: Field = 67890;
    let (cx, cy) = pedersen::commit(nullifier_seed, blinding_factor);

    let _ = main(
        1, 100, 1, 0, 0,
        1, 1, 5, 200,
        cx, cy,
        0, 0, 0, 0,
        nullifier_seed, blinding_factor,
        5,
    );
}

#[test(should_fail_with = "Invalid signature")]
fn test_reject_invalid_signature() {
    let nullifier_seed: Field = 12345;
    let blinding_factor: Field = 67890;
    let (cx, cy) = pedersen::commit(nullifier_seed, blinding_factor);

    // Use the known valid keypair from the schnorr regression test as issuer pubkey
    let pk_x: Field = 0x1bd2ca043010eba0fa5e958f0562792b2861e231c2fd59adf48f26b506a12e0b;
    let pk_y: Field = 0x21f7816e0233e455de2696cc40d5d51c5df34561740d84e17bc360b1aac892fb;

    // Use the generator G as R (valid curve point, but wrong signature)
    let r_x: Field = schnorr::G_X;
    let r_y: Field = schnorr::G_Y;

    let _ = main(
        1, 100, 1, pk_x, pk_y,
        1, 1, 1000, 200,
        cx, cy,
        r_x, r_y, 1, 0,
        nullifier_seed, blinding_factor,
        0,
    );
}
