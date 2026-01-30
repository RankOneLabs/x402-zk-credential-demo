// Utility functions for the circuit

/// Compare two field elements: a > b
/// Note: This assumes values are within a reasonable range (not close to field modulus)
pub fn field_gt(a: Field, b: Field) -> bool {
    // Convert to u64 for comparison (assumes values fit in u64)
    let a_int = a as u64;
    let b_int = b as u64;
    a_int > b_int
}

/// Compare two field elements: a < b
pub fn field_lt(a: Field, b: Field) -> bool {
    let a_int = a as u64;
    let b_int = b as u64;
    a_int < b_int
}

/// Compare two field elements: a >= b
pub fn field_gte(a: Field, b: Field) -> bool {
    let a_int = a as u64;
    let b_int = b as u64;
    a_int >= b_int
}

/// Compare two field elements: a <= b
pub fn field_lte(a: Field, b: Field) -> bool {
    let a_int = a as u64;
    let b_int = b as u64;
    a_int <= b_int
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
