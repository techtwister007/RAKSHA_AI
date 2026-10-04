# go-decoder — a Go target that ships no fuzz harness

`Decode([]byte) int` trusts a length byte and slices past the input: a runtime slice-bounds panic.
No fuzz test ships with it. RAKSHA discovers `Decode`, synthesizes a Go fuzz test, finds the panic
with native `go test -fuzz`, bounds the slice, and proves the fix through the gate.
