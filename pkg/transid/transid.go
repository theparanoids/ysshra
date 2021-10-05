package transid

import (
	"crypto/rand"
	"fmt"
)

// Generate generates 5-byte-long cryptographically secure pseudorandom transaction ID.
func Generate() string {
	transID := make([]byte, 5)
	rand.Read(transID)

	return fmt.Sprintf("%x", string(transID))
}
