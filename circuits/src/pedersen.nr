// Pedersen Commitment
// Uses Noir's std::hash::pedersen_commitment for compatibility with @aztec/bb.js
// 
// C = secret * G0 + blinding * G1
// Where G0, G1 are Barretenberg's default generators on Grumpkin.

use dep::std::hash::pedersen_commitment;
use dep::std::embedded_curve_ops::EmbeddedCurvePoint;

/// Compute Pedersen commitment using stdlib
/// Returns a point (x, y) that matches @aztec/bb.js pedersenCommit([secret, blinding])
pub fn commit(secret: Field, blinding: Field) -> (Field, Field) {
    let result: EmbeddedCurvePoint = pedersen_commitment([secret, blinding]);
    (result.x, result.y)
}

/// Verify a commitment opens to the given values
pub fn verify_opening(
    commitment_x: Field,
    commitment_y: Field,
    secret: Field,
    blinding: Field
) -> bool {
    let (expected_x, expected_y) = commit(secret, blinding);
    (commitment_x == expected_x) & (commitment_y == expected_y)
}

#[test]
fn test_commitment_deterministic() {
    let secret = 12345;
    let blinding = 67890;
    
    let (c1_x, c1_y) = commit(secret, blinding);
    let (c2_x, c2_y) = commit(secret, blinding);
    
    assert(c1_x == c2_x);
    assert(c1_y == c2_y);
}

#[test]
fn test_different_secrets_different_commitments() {
    let blinding = 12345;
    
    let (c1_x, c1_y) = commit(1, blinding);
    let (c2_x, c2_y) = commit(2, blinding);
    
    // Different secrets should produce different commitments
    assert((c1_x != c2_x) | (c1_y != c2_y));
}
