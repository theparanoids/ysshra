package transid

import "testing"

// TestGenerateTransID tests GenerateTransID to generate diff transaction ID.
func TestGenerateTransID(t *testing.T) {
	transid1 := Generate()
	if transid1 == "" {
		t.Errorf("generated trans ID should not be empty string")
	}
	transid2 := Generate()
	if transid2 == "" {
		t.Errorf("generated trans ID should not be empty string")
	}
	if transid1 == transid2 {
		t.Errorf("generated trans ID transid1(%q) and transid2(%q) should be different", transid1, transid2)
	}
}

// BenchmarkGenerate benchmarks how fast the Generate can generate transaction ID.
// The current benchmark is 182 ns/op on the local machine with 32 GB memory and 8 CPU cores.
func BenchmarkGenerate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Generate()
	}
}
