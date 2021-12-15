// Package backoff implements the backoff strategy for gRPC calls from client.
// https://github.com/grpc/grpc-go/blob/master/internal/backoff/backoff.go
package backoff

import (
	"math"
	"math/rand"
	"time"
)

// DefaultConfig is a backoff configuration with the default values
// specified at https://github.com/grpc/grpc/blob/master/doc/connection-backoff.md.
var DefaultConfig = Config{
	BaseDelay:  2.0 * time.Second,
	Multiplier: 3.0,
	MaxDelay:   15.0 * time.Second,
	Jitter:     0.2,
}

// Config defines the configuration options for backoff
type Config struct {
	// BaseDelay is the amount of time to backoff after the first failure.
	BaseDelay time.Duration
	// Multiplier is the factor with which to multiply backoffs after a
	// failed retry. Should ideally be greater than 1.
	Multiplier float64
	// MaxDelay is the upper bound of backoff delay.
	MaxDelay time.Duration
	// Jitter is the factor with which backoffs are randomized.
	Jitter float64
}

// Backoff returns the amount of time to wait before the next retry given the number
// of retries.
// https://github.com/grpc/proposal/blob/master/A6-client-retries.md#exponential-backoff
func (bc *Config) Backoff(attempt uint) time.Duration {
	if attempt == 0 {
		return bc.BaseDelay
	}
	backoff, max := float64(bc.BaseDelay), float64(bc.MaxDelay)
	backoff *= math.Pow(bc.Multiplier, float64(attempt))
	backoff = math.Min(backoff, max)
	// Randomize the backoff delay
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	backoff *= 1 + bc.Jitter*(r.Float64()*2-1)
	return time.Duration(backoff)
}
