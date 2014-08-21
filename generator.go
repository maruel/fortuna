// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed under the Apache License, Version 2.0
// that can be found in the LICENSE file.

// All the pages (p.) references are to Cryptography Engineering, N. Ferguson,
// B. Schneier, T. Kohno, ISBN 978-0-470-47424-2.

package fortuna

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"sync"
)

type generator struct {
	// Internal state
	lock               sync.Mutex
	key                []byte  // The current key is used to seed the next one.
	counter            counter // The counter is always 128 bytes since it is used as the IV for CTR.
	maxBytesPerRequest int

	// Cache.
	initialized bool      // false if bytes.Equal(counter, make(counter, len(counter)).
	temp        []byte    // Scratch space used when rekeying.
	h           hash.Hash // Hash object defines the security level. It is not used as a stateful member.
}

// NewGenerator returns an AES based cryptographic pseudo-random generator
// (PRNG) as described in p. 143.
//
// A generator generates arbitrary amounts of pseudorandom data from a smaller
// amount of seed data by running AES-256 in counter mode and re-keying after
// every maxBytesPerRequest of output.
//
// h is optional and defaults to SHA-256. This results in 128 bits of
// security.
//
// Reseeding is done via .Write() function.
//
// seed is optional. If seed is not provided, Write() must be called
// before calling Read(). The seed will deterministically determine the PRNG
// output. The resulting PRNG is guaranteed to not leak its internal state
// after each Read() call.
//
// The resulting object is thread-safe.
func NewGenerator(h hash.Hash, seed []byte) io.ReadWriter {
	g := newGenerator(h, seed)
	return &g
}

// newGenerator is used internally for the Accumulator to save a pointer
// dereference.
func newGenerator(h hash.Hash, seed []byte) generator {
	if h == nil {
		h = sha256.New()
	}
	b := h.Size()
	g := generator{
		key:                make([]byte, b),
		counter:            make([]byte, 16),
		maxBytesPerRequest: (1 << 15) * b,
		temp:               make([]byte, b),
		h:                  h,
	}
	if len(seed) != 0 {
		g.Write(seed)
	}
	return g
}

// Write updates the PRNG state with an arbitrary input string.
// Always update the counter on reseed.
func (g *generator) Write(data []byte) (int, error) {
	g.lock.Lock()
	defer g.lock.Unlock()

	g.key = DoubleHash(g.h, g.key, data)
	g.counter.incr()
	g.initialized = true
	return len(data), nil
}

// generateBlocks generates a number of blocks of random output into |out|.
//
// It generates random data by running in AES in CTR mode.
func (g *generator) generateBlocks(c cipher.Block, out []byte) {
	// Lock must be held by the caller.
	// Recall that c.BlockSize() == g.h.Size() / 2
	s := c.BlockSize()
	fullBlocks := len(out) / s
	// Generates as much PRNG data in-place as possible. This avoids an unneeded
	// memory copy.
	for i := 0; i < fullBlocks; i++ {
		// Do not use cipher.NewCTR(c, g.counter) for two reasons:
		// - M. Schneier prescribes a little endian counter but NewCTR() creates a
		//   streaming cipher that uses a big endian counter.
		// - The is not XORing being prescribed in the definition.
		b := i * s
		c.Encrypt(out[b:b+s], g.counter)
		g.counter.incr()
	}
	// Generates the last partial block in a temporary slice so only the bytes
	// needed can be put in the buffer.
	if len(out)%s != 0 {
		// We need to generate all the bytes then keep the ones needed.
		c.Encrypt(g.temp, g.counter)
		copy(out[fullBlocks*s:], g.temp)
		g.counter.incr()
	}
}

// Read reads pseudorandom data from the generator.
//
// A single Read reads at most maxBytesPerRequest bytes.
// This function is named PseudoRandomData in p. 146.
func (g *generator) Read(data []byte) (int, error) {
	g.lock.Lock()
	defer g.lock.Unlock()

	if !g.initialized {
		return 0, errors.New("Generator is not seeded")
	}

	if len(data) > g.maxBytesPerRequest {
		// The following description assumes using SHA-256:
		// p. 143
		// If we were to generate 2⁶⁴ blocks of output from a single key, we would
		// expect close to one collision on the block values. A few repeated
		// requests of this size would quickly show that the output is not perfectly
		// random; it lacks the expected block collisions. We limit the maximum size
		// of any one request to 2¹⁶ blocks (that is, 2²⁰ bytes). For an ideal
		// random generator, the probability of finding a block value collision in
		// 2¹⁶ output blocks is abour 2⁻⁹⁷, so the complete absense of collisions
		// would not be detectable until about 2⁹⁷ requests had been made. The total
		// workload for the attacker ends up being 2¹¹³ steps. Not quite the 2¹²⁸
		// steps that we're aiming for, but reasonably close.
		data = data[:g.maxBytesPerRequest]
	}
	// AES-128 or AES-256 will be selected depending on the key size:
	// - len(g.key) == 16 -> AES-128
	// - len(g.key) == 32 -> AES-256
	c, err := aes.NewCipher(g.key)
	if err != nil {
		panic(err) // Only possible error is bad key size.
	}
	g.generateBlocks(c, data)

	// p. 143
	// Suppose an attacker manages to compromise the generator's state after the
	// completion of the request. It would be nice if this would not compromise
	// the previous results the generator gave. Therefore, after every request we
	// generate an extra 256 bits of pseudorandom data and use that as the new
	// key for the block cipher. We can then forget the old key, thereby
	// eliminating any possibility of leaking information about old requests.
	g.generateBlocks(c, g.key)
	return len(data), nil
}
