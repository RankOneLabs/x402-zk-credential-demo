// Utility functions for the circuit

/// Compare two field elements: a > b
/// IMPORTANT: Only valid for values that fit in u64 (e.g., timestamps, counters).
/// Will fail assertion for larger field values to prevent silent incorrect results.
pub fn field_gt(a: Field, b: Field) -> bool {
    // Assert values fit in u64 to prevent silent overflow
    assert(field_fits_u64(a), "field_gt: 'a' exceeds u64 range");
    assert(field_fits_u64(b), "field_gt: 'b' exceeds u64 range");
    
    let a_int = a as u64;
    let b_int = b as u64;
    a_int > b_int
}

/// Compare two field elements: a < b
/// IMPORTANT: Only valid for values that fit in u64.
pub fn field_lt(a: Field, b: Field) -> bool {
    assert(field_fits_u64(a), "field_lt: 'a' exceeds u64 range");
    assert(field_fits_u64(b), "field_lt: 'b' exceeds u64 range");
    
    let a_int = a as u64;
    let b_int = b as u64;
    a_int < b_int
}

/// Compare two field elements: a >= b
/// IMPORTANT: Only valid for values that fit in u64.
pub fn field_gte(a: Field, b: Field) -> bool {
    assert(field_fits_u64(a), "field_gte: 'a' exceeds u64 range");
    assert(field_fits_u64(b), "field_gte: 'b' exceeds u64 range");
    
    let a_int = a as u64;
    let b_int = b as u64;
    a_int >= b_int
}

/// Compare two field elements: a <= b
/// IMPORTANT: Only valid for values that fit in u64.
pub fn field_lte(a: Field, b: Field) -> bool {
    assert(field_fits_u64(a), "field_lte: 'a' exceeds u64 range");
    assert(field_fits_u64(b), "field_lte: 'b' exceeds u64 range");
    
    let a_int = a as u64;
    let b_int = b as u64;
    a_int <= b_int
}

/// Check if a field element fits within u64 range
fn field_fits_u64(f: Field) -> bool {
    // Decompose and check: f <= MAX_U64
    // We use byte decomposition to check the value fits
    let bytes = f.to_le_bytes::<32>();
    // Check bytes 8..32 are all zero (only lower 8 bytes can be non-zero for u64)
    let mut fits = true;
    for i in 8..32 {
        if bytes[i] != 0 {
            fits = false;
        }
    }
    fits
}

#[test]
fn test_field_comparisons() {
    assert(field_gt(10, 5));
    assert(!field_gt(5, 10));
    assert(!field_gt(5, 5));
    
    assert(field_lt(5, 10));
    assert(!field_lt(10, 5));
    assert(!field_lt(5, 5));
    
    assert(field_gte(10, 5));
    assert(field_gte(5, 5));
    assert(!field_gte(5, 10));
    
    assert(field_lte(5, 10));
    assert(field_lte(5, 5));
    assert(!field_lte(10, 5));
}

#[test]
fn test_field_fits_u64() {
    // Max u64 should fit
    let max_u64: Field = 18446744073709551615;
    assert(field_fits_u64(max_u64));
    
    // Small values should fit
    assert(field_fits_u64(0));
    assert(field_fits_u64(1));
    assert(field_fits_u64(1000000000));
    
    // Typical timestamp should fit (year 2026 in seconds)
    assert(field_fits_u64(1767225600)); // Jan 1, 2026
}

#[test]
fn test_field_fits_u64_overflow() {
    // Value larger than u64 should not fit
    // 2^64 = 18446744073709551616
    let too_big: Field = 18446744073709551616;
    assert(!field_fits_u64(too_big));
    
    // Much larger value
    let very_big: Field = 0x100000000000000000; // 2^64 in hex
    assert(!field_fits_u64(very_big));
}
