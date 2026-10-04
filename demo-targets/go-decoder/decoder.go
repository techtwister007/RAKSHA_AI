// Package decoder parses a tiny length-prefixed wire format. It ships no fuzz harness — RAKSHA
// synthesizes a Go fuzz test, finds the panic with native fuzzing, fixes it and proves the fix.
package decoder

// Decode reads records of the form [length][length bytes...]. BUG: it trusts the length byte and
// slices past the end of the input, panicking with an index/slice out-of-range at runtime.
func Decode(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	n := int(data[0])
	body := data[1 : 1+n] // slice bounds out of range when 1+n > len(data)
	sum := 0
	for _, b := range body {
		sum += int(b)
	}
	return sum
}
