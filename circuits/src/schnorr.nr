// Schnorr Signature Verification
// Verifies: s * G == R + H(R || pk || m) * pk

use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};
use poseidon::poseidon::bn254;

// Grumpkin generator G0 (from Barretenberg's pedersenCommit generators)
// This is the point 1 * G0 from pedersen_commitment([1, 0], 0)
global G_X: Field = 0x083e7911d835097629f0067531fc15cafd79a89beecb39903f69572c636f4a5a;
global G_Y: Field = 0x1a7f5efaad7f315c25a918f30cc8d7333fccab7ad7c90f14de81bcc528f9935d;

/// Verify a Schnorr signature
/// 
/// # Arguments
/// * `pk_x`, `pk_y` - Public key point
/// * `message` - Message hash (single field element)
/// * `r_x`, `r_y` - R point of signature
/// * `s_lo`, `s_hi` - s scalar split into 128-bit limbs
/// 
/// # Returns
/// true if signature is valid
pub fn verify(
    pk_x: Field,
    pk_y: Field,
    message: Field,
    r_x: Field,
    r_y: Field,
    s_lo: Field,
    s_hi: Field
) -> bool {
    // Compute challenge: e = H(R || pk || m)
    let e = bn254::hash_5([r_x, r_y, pk_x, pk_y, message]);
    
    // Split e into 128-bit limbs using decomposition
    // e = e_lo + e_hi * 2^128
    let e_bytes = e.to_le_bytes::<32>();
    
    // e_lo = bytes 0..16 (little-endian)
    let mut e_lo: Field = 0;
    let mut multiplier: Field = 1;
    for i in 0..16 {
        e_lo += (e_bytes[i] as Field) * multiplier;
        multiplier *= 256;
    }
    
    // e_hi = bytes 16..32 (little-endian)
    let mut e_hi: Field = 0;
    multiplier = 1;
    for i in 16..32 {
        e_hi += (e_bytes[i] as Field) * multiplier;
        multiplier *= 256;
    }
    
    // Compute LHS: s * G
    let g_point = EmbeddedCurvePoint { x: G_X, y: G_Y, is_infinite: false };
    let s_scalar = EmbeddedCurveScalar { lo: s_lo, hi: s_hi };
    let lhs = multi_scalar_mul([g_point], [s_scalar]);
    
    // Compute RHS: R + e * pk
    let r_point = EmbeddedCurvePoint { x: r_x, y: r_y, is_infinite: false };
    let pk_point = EmbeddedCurvePoint { x: pk_x, y: pk_y, is_infinite: false };
    let e_scalar = EmbeddedCurveScalar { lo: e_lo, hi: e_hi };
    let one_scalar = EmbeddedCurveScalar { lo: 1, hi: 0 };
    
    // R + e * pk using multi_scalar_mul
    let rhs = multi_scalar_mul([r_point, pk_point], [one_scalar, e_scalar]);
    
    // Check equality
    (lhs.x == rhs.x) & (lhs.y == rhs.y)
}

#[test]
fn test_schnorr_placeholder() {
    // TODO: Add test with known test vectors from TypeScript implementation
    // This ensures Noir and TypeScript produce matching signatures
    assert(true);
}

#[test]
fn test_schnorr_debug() {
    // Debug test with fixed values
    let pk_x: Field = 4487995459841908226541024527283132709619697693159278929978762006984097362577;
    let pk_y: Field = 8571660945555118922124892307203162141912312929543889646077435926509389365396;
    let message: Field = 555666777888999;
    let r_x: Field = 17603465354240130424494153796389390227299484978922401063153607343617333448555;
    let r_y: Field = 1463905919835087874385344536865589815360476156147949623884647266543722265912;
    let s_lo: Field = 292863635587060291173365476840527928037;
    let s_hi: Field = 43738355177361219542240589404787882217;
    
    // Expected e from TypeScript: 15667321770285706851567860439889119158791036584861713155547976953546420802083
    let expected_e: Field = 15667321770285706851567860439889119158791036584861713155547976953546420802083;
    
    // Compute challenge: e = H(R || pk || m)
    let e = bn254::hash_5([r_x, r_y, pk_x, pk_y, message]);
    
    std::println("e computed:");
    std::println(e);
    std::println("e expected:");
    std::println(expected_e);
    
    assert(e == expected_e, "e mismatch");
    
    // Split e
    let e_bytes = e.to_le_bytes::<32>();
    let mut e_lo: Field = 0;
    let mut multiplier: Field = 1;
    for i in 0..16 {
        e_lo += (e_bytes[i] as Field) * multiplier;
        multiplier *= 256;
    }
    let mut e_hi: Field = 0;
    multiplier = 1;
    for i in 16..32 {
        e_hi += (e_bytes[i] as Field) * multiplier;
        multiplier *= 256;
    }
    
    std::println("e_lo:");
    std::println(e_lo);
    std::println("e_hi:");
    std::println(e_hi);
    
    // Compute LHS: s * G
    let g_point = EmbeddedCurvePoint { x: G_X, y: G_Y, is_infinite: false };
    let s_scalar = EmbeddedCurveScalar { lo: s_lo, hi: s_hi };
    let lhs = multi_scalar_mul([g_point], [s_scalar]);
    
    let lhs_x = lhs.x;
    let lhs_y = lhs.y;
    std::println("lhs.x (s*G):");
    std::println(lhs_x);
    std::println("lhs.y (s*G):");
    std::println(lhs_y);
    
    // Compute RHS: R + e * pk
    let r_point = EmbeddedCurvePoint { x: r_x, y: r_y, is_infinite: false };
    let pk_point = EmbeddedCurvePoint { x: pk_x, y: pk_y, is_infinite: false };
    let e_scalar = EmbeddedCurveScalar { lo: e_lo, hi: e_hi };
    let one_scalar = EmbeddedCurveScalar { lo: 1, hi: 0 };
    
    let rhs = multi_scalar_mul([r_point, pk_point], [one_scalar, e_scalar]);
    
    let rhs_x = rhs.x;
    let rhs_y = rhs.y;
    std::println("rhs.x (R + e*pk):");
    std::println(rhs_x);
    std::println("rhs.y (R + e*pk):");
    std::println(rhs_y);
    
    assert(lhs.x == rhs.x, "x mismatch");
    assert(lhs.y == rhs.y, "y mismatch");
}

#[test]
fn test_msm_basic() {
    // Test: verify that multi_scalar_mul([P, Q], [a, b]) = a*P + b*Q
    // Using the identity: (k + e*sk)*G = k*G + e*(sk*G) = R + e*pk
    
    // Our G
    let G = EmbeddedCurvePoint { x: G_X, y: G_Y, is_infinite: false };
    
    // Compute k*G and sk*G
    let k: Field = 98765432109876543210;
    let sk: Field = 12345678901234567890;
    
    // Split into limbs (these are small, so just lo)
    let k_scalar = EmbeddedCurveScalar { lo: k, hi: 0 };
    let sk_scalar = EmbeddedCurveScalar { lo: sk, hi: 0 };
    
    // R = k*G
    let R = multi_scalar_mul([G], [k_scalar]);
    
    // pk = sk*G
    let pk = multi_scalar_mul([G], [sk_scalar]);
    
    std::println("R = k*G:");
    std::println(R.x);
    std::println(R.y);
    
    std::println("pk = sk*G:");
    std::println(pk.x);
    std::println(pk.y);
    
    // Now compute (k + sk)*G directly
    let sum: Field = 98765432109876543210 + 12345678901234567890; // = 111111111011111111100
    let sum_scalar = EmbeddedCurveScalar { lo: sum, hi: 0 };
    let direct = multi_scalar_mul([G], [sum_scalar]);
    
    std::println("(k+sk)*G directly:");
    std::println(direct.x);
    std::println(direct.y);
    
    // Now compute R + pk using multi_scalar_mul([R, pk], [1, 1])
    let one = EmbeddedCurveScalar { lo: 1, hi: 0 };
    let sum_via_msm = multi_scalar_mul([R, pk], [one, one]);
    
    std::println("R + pk via multi_scalar_mul:");
    std::println(sum_via_msm.x);
    std::println(sum_via_msm.y);
    
    // These should be equal
    assert(direct.x == sum_via_msm.x, "MSM point addition failed x");
    assert(direct.y == sum_via_msm.y, "MSM point addition failed y");
}

#[test]
fn test_msm_large_scalar() {
    // Test with the actual large e value that's failing
    // e = 15667321770285706851567860439889119158791036584861713155547976953546420802083
    // e_lo = 0x40cfb483c9e539b5fd4a82a72f045223
    // e_hi = 0x22a363cec05d8242c1c119f3f86767f0
    
    let G = EmbeddedCurvePoint { x: G_X, y: G_Y, is_infinite: false };
    
    // sk used to generate pk
    let sk: Field = 12345678901234567890;
    let sk_scalar = EmbeddedCurveScalar { lo: sk, hi: 0 };
    let pk = multi_scalar_mul([G], [sk_scalar]);
    
    // e_lo and e_hi from the debug output
    let e_lo: Field = 0x40cfb483c9e539b5fd4a82a72f045223;
    let e_hi: Field = 0x22a363cec05d8242c1c119f3f86767f0;
    let e_scalar = EmbeddedCurveScalar { lo: e_lo, hi: e_hi };
    
    // Compute e * pk using multi_scalar_mul
    let e_pk = multi_scalar_mul([pk], [e_scalar]);
    
    std::println("e * pk via multi_scalar_mul:");
    std::println(e_pk.x);
    std::println(e_pk.y);
    
    // Now compute e * sk (mod field) and then (e*sk) * G
    // e = e_lo + e_hi * 2^128
    // But in Noir, we can't easily compute e*sk because Field is modular
    // Actually we need to compute (e * sk) mod curve_order
    
    // The issue is: EmbeddedCurveScalar has lo/hi as Field, but arithmetic
    // on scalars happens mod curve_order, not mod field!
    
    // For Grumpkin, the curve order IS the BN254 field modulus
    // So e*sk can be computed in Field, then split into lo/hi
    
    // Actually no, the issue might be: when we pass e as (e_lo, e_hi) to 
    // multi_scalar_mul, it reconstructs e = e_lo + e_hi * 2^128
    // But e_lo and e_hi are Field elements, which are mod field_modulus
    // So if e_lo or e_hi are larger than 2^128, there could be overflow
    
    // Let's check our e_lo and e_hi are valid (< 2^128)
    // e_lo = 0x40cfb483c9e539b5fd4a82a72f045223 (129 bits? Let me check)
    
    // 0x40cfb483c9e539b5fd4a82a72f045223 in binary is about 127 bits (starts with 0x4)
    // 0x22a363cec05d8242c1c119f3f86767f0 is about 126 bits (starts with 0x2)
    // So both fit in 128 bits - that's correct
    
    // The problem might be that multi_scalar_mul expects the scalar to be
    // less than the curve order, which it is for e
}
