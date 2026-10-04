//! A tiny length-prefixed record decoder that ships NO fuzz harness.
//!
//! `parse_record(&[u8]) -> i32` trusts a length byte and slices past the end of the input, so a
//! crafted record panics at runtime with a slice-range / index-out-of-bounds. RAKSHA discovers
//! `parse_record`, synthesizes a `cargo test` harness, finds the panic by mutation, clamps the
//! slice, and proves the fix through the same five-check gate as C, Go, Java and Python.

/// Parse one `[tag][len][len bytes...]` record and return the checksum of its body.
///
/// BUG: `len` (the second byte) is trusted and used to slice the body without being bounded against
/// the input length, so `&data[2..2 + n]` runs off the end and panics (range end out of range).
/// Short inputs take a benign early-return path, so a corpus of small seeds does not all panic.
pub fn parse_record(data: &[u8]) -> i32 {
    if data.len() < 2 {
        return 0; // too short to carry a record header — nothing to decode
    }
    let n = data[1] as usize; // declared body length, trusted from the wire
    let body = &data[2..2 + n]; // BUG: unbounded — panics when 2 + n > data.len()
    let mut sum: i32 = 0;
    for &b in body {
        sum += b as i32;
    }
    sum
}
