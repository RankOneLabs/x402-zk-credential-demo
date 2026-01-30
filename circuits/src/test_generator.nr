// Test to verify multi_scalar_mul generator matches bb.js pedersenCommit
// Run with: nargo test

use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};
use poseidon::poseidon::bn254;
use super::schnorr;

// Grumpkin G0 from bb.js pedersenCommit([1, 0], 0)
global G_X: Field = 0x083e7911d835097629f0067531fc15cafd79a89beecb39903f69572c636f4a5a;
global G_Y: Field = 0x1a7f5efaad7f315c25a918f30cc8d7333fccab7ad7c90f14de81bcc528f9935d;

#[test]
fn test_generator_scalar_mul() {
    // Test: 1 * G = G
    let g_point = EmbeddedCurvePoint { x: G_X, y: G_Y, is_infinite: false };
    let one = EmbeddedCurveScalar { lo: 1, hi: 0 };
    
    let result = multi_scalar_mul([g_point], [one]);
    
    assert(result.x == G_X, "1*G should give G.x");
    assert(result.y == G_Y, "1*G should give G.y");
}

#[test]
fn test_scalar_mul_2() {
    // Test: 2 * G - compare with bb.js pedersenCommit([2, 0], 0)
    // bb.js gives:
    // x: 21257496462400913801282840561021446049249742519529950649510548656246698707241n
    // y: 9311206937097351457745531264432686767848437768817720608527154146862405004551n
    
    let g_point = EmbeddedCurvePoint { x: G_X, y: G_Y, is_infinite: false };
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
    // poseidon5([1, 2, 3, 4, 5]) in TypeScript = ?
    // Let's compute: node -e "import('poseidon-lite').then(m => console.log(m.poseidon5([1n, 2n, 3n, 4n, 5n]).toString()))"
    // Result: 16242028851tried...
    
    // Actually just run a test with known values from our trace
    // R.x, R.y, pk.x, pk.y, msg from trace_pipeline.mjs
    let r_x: Field = 15586508460521873282303391413110255770263182162137576975730309916872770142204;
    let r_y: Field = 9420586946860869436254880928007827325718023123652385066948200280470791944746;
    let pk_x: Field = 12022637569576473379573069991111364863938392389331499657725472749980125389546;
    let pk_y: Field = 6632891716358796814110547996021089181016285457448024828751559989112352485265;
    let msg: Field = 5218754217353592738684666472458211292743397235479628375008864193561994863584;
    
    let e = bn254::hash_5([r_x, r_y, pk_x, pk_y, msg]);
    
    // Expected from TypeScript: 17256779402336672062762749904870990518038154892151539523702343666365749047318n
    let expected: Field = 17256779402336672062762749904870990518038154892151539523702343666365749047318;
    
    assert(e == expected, "Poseidon hash_5 mismatch with TypeScript");
}

#[test]
fn test_poseidon7() {
    // Test Poseidon hash_7 matches poseidon-lite's poseidon7
    // Values from trace_pipeline:
    // [1, 1, 1000, 1706547800, 1800000000, commitment_x, commitment_y]
    let inputs = [
        1,    // service_id
        1,    // tier
        1000, // max_presentations
        1706547800, // issued_at
        1800000000, // expires_at
        1174064385289564629069614027811202315496463851600307037813143587535931871049, // commitment_x
        17728503547603906361997519818252527060372219074479031690013921614517041679708  // commitment_y
    ];
    
    let msg = bn254::hash_7(inputs);
    
    // Expected from TypeScript: 5218754217353592738684666472458211292743397235479628375008864193561994863584n
    let expected: Field = 5218754217353592738684666472458211292743397235479628375008864193561994863584;
    
    assert(msg == expected, "Poseidon hash_7 mismatch with TypeScript");
}

#[test]
fn test_schnorr_verify() {
    // Test Schnorr verification with fixed test vectors from TypeScript
    // Signature: s*G == R + e*pk where e = H(R || pk || msg)
    
    let pk_x: Field = 4487995459841908226541024527283132709619697693159278929978762006984097362577;
    let pk_y: Field = 8571660945555118922124892307203162141912312929543889646077435926509389365396;
    let message: Field = 555666777888999;
    let r_x: Field = 17603465354240130424494153796389390227299484978922401063153607343617333448555;
    let r_y: Field = 1463905919835087874385344536865589815360476156147949623884647266543722265912;
    let s_lo: Field = 292863635587060291173365476840527928037;
    let s_hi: Field = 43738355177361219542240589404787882217;
    
    let result = schnorr::verify(pk_x, pk_y, message, r_x, r_y, s_lo, s_hi);
    assert(result, "Schnorr signature should verify");
}
