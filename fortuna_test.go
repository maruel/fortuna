// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed under the Apache License, Version 2.0
// that can be found in the LICENSE file.

package fortuna

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// Base64 encoding of bytes from 00 to 7F.
const seed = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8="

func newFortuna(t *testing.T) *accumulator {
	raw, err := base64.StdEncoding.DecodeString(seed)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewFortuna(raw)
	if err != nil {
		t.Fatal(err)
	}
	return reader.(*accumulator)
}

// Make sure at most 2<<16 bytes are read.
func TestLimit(t *testing.T) {
	t.Parallel()
	prng := newFortuna(t)
	maxBytesPerRequest := 1 << 20
	data := make([]byte, maxBytesPerRequest+1)
	read(t, prng, data, maxBytesPerRequest)
}

func TestMinSeed(t *testing.T) {
	t.Parallel()
	raw := [2*minPoolSize - 1]byte{}
	_, err := NewFortuna(raw[:])
	if err == nil {
		t.Error("No error set")
	}
}

// Fetches a numBytes bytes block maxTries times.
//
// It should never be the same return value for the same seed. Define X =
// 2<<(8*numBytes). The theorical probability of this happening is
// P( X! / (X^maxTries * (X-maxTries)!) ).
func bruteForce(t *testing.T, name string, maxTries, numBytes int, read func([]byte)) {
	blocks := map[string]bool{}
	for i := 0; i < maxTries; i++ {
		data := make([]byte, numBytes)
		read(data)
		str := string(data)
		if blocks[str] {
			t.Fatalf("The PRNG %s returned the same %d bytes blocks 2 times after %d requests (out of %d): %v", name, numBytes, i, maxTries, data)
		}
		blocks[str] = true
	}
}

func TestEntropySourceRandom(t *testing.T) {
	t.Parallel()
	// Get the same 4 bytes in 4 tries.
	bruteForce(t, "crypto/rand", 4, 4, func(data []byte) {
		n, err := rand.Read(data)
		if n != len(data) || err != nil {
			t.Fatal("Internal failure reading randomness")
		}
	})
}

func TestEntropyFortuna(t *testing.T) {
	t.Parallel()
	prng := newFortuna(t)
	// At that point, the accumulator is in a somewhat deterministic state.
	// Entropy was added via time.Now() but creating two instances twice
	// sufficiently fast will result in objects with the exact same internal
	// state. Entropy must be added via AddRandomEvent().
	if prng.numReseed != 1 {
		t.Fatalf("Got %d", prng.numReseed)
	}
	// This takes at least reseedInterval (100ms) to complete. Sadly, this slow
	// down the test by a bit more than 100ms.
	entropy := make([]byte, 32)
	buffer := make([]byte, 1)
	for {
		// Add fake entropy. In practice you want to use real entropy.
		prng.AddRandomEvent(1, entropy)
		read(t, prng, buffer, 1)
		if prng.numReseed == 2 {
			// This can only happen after reseedInterval has passed and at least
			// minPoolSize was written to the first pool.
			break
		}
	}
}

// Benches large chunks throughput. Calculates the cost per byte.
func BenchmarkFortunaLarge(b *testing.B) {
	f, err := NewFortuna(make([]byte, 128))
	if err != nil {
		b.Fatal(err)
	}
	data := make([]byte, b.N)
	count := 0
	b.ResetTimer()

	for count != b.N {
		// For large values of b.N, the Read call will only return up to
		// maxBytesPerRequest bytes so a loop is needed. In theory it will increase
		// overhead, in practice maxBytesPerRequest is large enough that overhead
		// is minimal.
		remaining := b.N - count
		n, err := f.Read(data[:remaining])
		if err != nil {
			b.Fatal(err)
		}
		if n == 0 {
			b.Fatalf("Failed to read")
		}
		count += n
	}
}

// Reads 1 byte at a time to bench overhead. Calculates the cost per byte.
func BenchmarkFortuna1Byte(b *testing.B) {
	f, err := NewFortuna(make([]byte, 128))
	if err != nil {
		b.Fatal(err)
	}
	data := make([]byte, 1)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		n, err := f.Read(data)
		if err != nil {
			b.Fatal(err)
		}
		if n != 1 {
			b.Fatalf("Failed to read")
		}
	}
}

// Reads 16 bytes at a time to bench overhead. Calculates the cost per byte.
func BenchmarkFortuna16Bytes(b *testing.B) {
	f, err := NewFortuna(make([]byte, 128))
	if err != nil {
		b.Fatal(err)
	}
	data := make([]byte, 16)
	count := 0
	b.ResetTimer()

	for count != b.N {
		chunk := 16
		if b.N-count < 16 {
			chunk = b.N - count
		}
		n, err := f.Read(data[:chunk])
		if err != nil {
			b.Fatal(err)
		}
		if n != chunk {
			b.Fatalf("Failed to read")
		}
		count += chunk
	}
}

// Adds random event. Calculates the cost per adding random event.
func BenchmarkFortunaAddRandomEvent(b *testing.B) {
	f, err := NewFortuna(make([]byte, 128))
	if err != nil {
		b.Fatal(err)
	}
	data := make([]byte, 16)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		f.AddRandomEvent(0, data)
	}
}
