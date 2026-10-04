# rust-nolibfuzzer — a Rust crate that ships no fuzz harness

`parse_record(&[u8]) -> i32` trusts a length byte and slices past the input: a runtime
slice-range / index-out-of-bounds panic. No `cargo-fuzz` target, no hand-written harness ships
with it. RAKSHA discovers `parse_record`, synthesizes a `cargo test` harness, finds the panic by
mutation (stable `cargo test`, offline — no cargo-fuzz/nightly), clamps the slice, and proves the
fix through the shared five-check gate.
