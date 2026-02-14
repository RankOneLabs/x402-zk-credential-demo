// Test to verify multi_scalar_mul generator matches bb.js pedersenCommit
// Run with: nargo test

use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};
use poseidon::poseidon::bn254;
use super::schnorr;

#[test]
fn test_generator_scalar_mul() {
    // Test: 1 * G = G
    let g_point = EmbeddedCurvePoint { x: schnorr::G_X, y: schnorr::G_Y, is_infinite: false };
    let one = EmbeddedCurveScalar { lo: 1, hi: 0 };
    
    let result = multi_scalar_mul([g_point], [one]);
    
    assert(result.x == schnorr::G_X, "1*G should give G.x");
    assert(result.y == schnorr::G_Y, "1*G should give G.y");
}

#[test]
fn test_scalar_mul_2() {
    // Test: 2 * G - compare with bb.js pedersenCommit([2, 0], 0)
    // bb.js gives:
    // x: 21257496462400913801282840561021446049249742519529950649510548656246698707241n
    // y: 9311206937097351457745531264432686767848437768817720608527154146862405004551n
    
    let g_point = EmbeddedCurvePoint { x: schnorr::G_X, y: schnorr::G_Y, is_infinite: false };
    let two = EmbeddedCurveScalar { lo: 2, hi: 0 };
    
    let result = multi_scalar_mul([g_point], [two]);
    
    // Check against bb.js values
    let expected_x: Field = 21257496462400913801282840561021446049249742519529950649510548656246698707241;
    let expected_y: Field = 9311206937097351457745531264432686767848437768817720608527154146862405004551;
    
    assert(result.x == expected_x, "2*G.x mismatch");
    assert(result.y == expected_y, "2*G.y mismatch");
}

#[test]
fn test_poseidon5() {
    // Test Poseidon hash_5 matches poseidon-lite's poseidon5
    // Values from debug_crypto.mjs (consistent with other tests)
    let r_x: Field = 1182763979350526475212485930157366542283664705518667046707933006366861600632;
    let r_y: Field = 4346731876452038345383167266747365772560026138985344951090222648742511279903;
    let pk_x: Field = 15108953930137042819513034131958662671218887081582774949540239272677568601742;
    let pk_y: Field = 21043406075889108463128184971281524910665729290620561953998734705800085846760;
    let msg: Field = 5218754217353592738684666472458211292743397235479628375008864193561994863584;
    
    let e = bn254::hash_5([r_x, r_y, pk_x, pk_y, msg]);
    
    // Expected from TypeScript: 10189863774461557634767823164107053144697691595359729908754784245260991416991
    let expected: Field = 10189863774461557634767823164107053144697691595359729908754784245260991416991;
    
    assert(e == expected, "Poseidon hash_5 mismatch with TypeScript");
}

#[test]
fn test_poseidon6() {
    // Test Poseidon hash_6 matches poseidon-lite's poseidon6
    // [service_id, tier, identity_limit, expires_at, commitment_x, commitment_y]
    // (issued_at removed from credential hash for privacy)
    let inputs = [
        1,    // service_id
        1,    // tier
        1000, // identity_limit
        1800000000, // expires_at
        1174064385289564629069614027811202315496463851600307037813143587535931871049, // commitment_x
        17728503547603906361997519818252527060372219074479031690013921614517041679708  // commitment_y
    ];
    
    let msg = bn254::hash_6(inputs);
    
    // Expected from TypeScript poseidon6: matches poseidon-lite/circomlibjs
    let expected: Field = 2541811923401058266366024049633353933549547690240374137055738783998965528825;
    assert(msg == expected, "Poseidon hash_6 mismatch with TypeScript");
}

#[test]
fn test_schnorr_verify() {
    // Test Schnorr verification with fixed test vectors from TypeScript (debug_crypto.mjs)
    // Signature: s*G == R + e*pk where e = H(R || pk || msg)
    
    let pk_x: Field = 15108953930137042819513034131958662671218887081582774949540239272677568601742;
    let pk_y: Field = 21043406075889108463128184971281524910665729290620561953998734705800085846760;
    
    let message: Field = 5218754217353592738684666472458211292743397235479628375008864193561994863584;
    
    let r_x: Field = 1182763979350526475212485930157366542283664705518667046707933006366861600632;
    let r_y: Field = 4346731876452038345383167266747365772560026138985344951090222648742511279903;
    
    let s_lo: Field = 293797380005494661284480189873502983604;
    let s_hi: Field = 6278642313871932327841515460057262405;
    
    let result = schnorr::verify(pk_x, pk_y, message, r_x, r_y, s_lo, s_hi);
    assert(result, "Schnorr signature should verify");
}