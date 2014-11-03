// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed under the Apache License, Version 2.0
// that can be found in the LICENSE file.

package fortuna

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

type generatorLenTest struct {
	h        hash.Hash
	request  int
	expected int
}

var generatorLenTestData = []generatorLenTest{
	// 64 bits of security (128/2).
	{md5.New(), 1024, 1024},
	// Maximum data is 512kb.
	{md5.New(), 4 * 1024 * 1024, 512 * 1024},
	// 128 bits of security (256/2).
	{sha256.New(), 1024, 1024},
	// Maximum data is 1Mb.
	{sha256.New(), 8 * 1024 * 1024, 1024 * 1024},
}

func init() {
	// Enable parallel execution if not already enabled.
	// These tests are highly CPU intensive and the scale linearly with NumCPU.
	if runtime.GOMAXPROCS(0) == 1 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}
}

func TestnewGeneratorDefault(t *testing.T) {
	t.Parallel()
	g := newGenerator(sha256.New(), nil)
	if g.h.Size() != 32 {
		t.Fatal("Unexpected default")
	}
	g = newGenerator(sha256.New(), []byte{})
	if g.h.Size() != 32 {
		t.Fatal("Unexpected default")
	}
}

// Compress data and returns the resulting size.
func compress(t *testing.T, d []byte) int {
	buf := &bytes.Buffer{}
	// It's a bit slow, flate.BestSpeed could be used but that would go against
	// the check here.
	f, err := flate.NewWriter(buf, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if i, err := f.Write(d); err != nil {
		t.Fatal(err)
	} else if i != len(d) {
		t.Fatal("Unexpected len")
	}
	f.Flush()
	return buf.Len()
}

// Reads data and ensures this is the expected size.
func read(t *testing.T, r io.Reader, out []byte, expected int) {
	l, err := r.Read(out)
	if err != nil {
		t.Fatal(err)
	}
	if l != expected {
		t.Fatalf("Requested %d, expected %d, got %d", len(out), expected, l)
	}
}

func testGeneratorLen(t *testing.T, i int, s generatorLenTest) {
	g := NewGenerator(s.h, []byte{0})
	d := make([]byte, s.request)
	read(t, g, d, s.expected)

	// Verify that the data is not compressible.
	// Note that it's not using d[:l] but the whole buffer. The reason is that
	// otherwise flate will go on the quick path skip compression, so the result
	// is not useful.
	compressed := compress(t, d)
	ratio := float64(compressed) / float64(s.expected)
	// Data will be larger because of the flate header.
	if ratio < 1. {
		t.Fatalf("%d H:%d; data is too compressible: %.1f %d -> %d\n%v", i, s.h.Size(), ratio*100., s.expected, compressed, d)
	}
	// Make sure the 0-filled block at the end is compressed.
	if compressed > (s.expected+8192) || ratio > 1.1 {
		t.Fatalf("%d H:%d; data is not enough compressed: %.1f %d -> %d", i, s.h.Size(), ratio*100., s.expected, compressed)
	}
}

func TestGeneratorCutShort(t *testing.T) {
	t.Parallel()
	// This test is CPU intensive so parallelize as much as possible.
	var wg sync.WaitGroup
	for index, line := range generatorLenTestData {
		wg.Add(1)
		go func(i int, s generatorLenTest) {
			defer wg.Done()
			testGeneratorLen(t, i, s)
		}(index, line)
	}
	wg.Wait()
}

type blockRead struct {
	Len      int
	Expected []byte
}

type generatorTestData struct {
	Input    []byte
	Expected []blockRead
}

func loadGeneratorTestData(t *testing.T, name string) []generatorTestData {
	content, err := ioutil.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var data []generatorTestData
	if err = json.Unmarshal(content, &data); err != nil {
		t.Fatal(err)
	}
	return data
}

// Ensures Generator is completely deterministic and has the exact same output
// than the python implementation.
func TestGeneratorDeterminism(t *testing.T) {
	t.Parallel()
	for i, v := range loadGeneratorTestData(t, "generator.json") {
		{
			g1 := NewGenerator(nil, v.Input)
			for j, e := range v.Expected {
				d := make([]byte, e.Len)
				read(t, g1, d, e.Len)
				if 0 != bytes.Compare(e.Expected, d) {
					t.Fatalf("Index %d,%d: Generator.Read(%d) -> %v != %v", i, j, e.Len, d, e.Expected)
				}
			}
		}

		// Late reseeding results in the same output and that the output data is
		// properly overwritten.
		{
			g2 := NewGenerator(nil, nil)
			g2.Write(v.Input)
			for j, e := range v.Expected {
				d := make([]byte, e.Len)
				read(t, g2, d, e.Len)
				if 0 != bytes.Compare(e.Expected, d) {
					t.Fatalf("Index %d,%d: Generator.Read(%d) -> %v != %v", i, j, e.Len, d, e.Expected)
				}
			}
		}
	}
}

// Benches large chunks throughput. Calculates the cost per byte.
func BenchmarkGeneratorLarge(b *testing.B) {
	g := NewGenerator(nil, []byte{0})
	data := make([]byte, b.N)
	count := 0
	b.ResetTimer()

	for count != b.N {
		// For large values of b.N, the Read call will only return up to
		// maxBytesPerRequest bytes so a loop is needed. In theory it will increase
		// overhead, in practice maxBytesPerRequest is large enough that overhead
		// is minimal.
		remaining := b.N - count
		n, err := g.Read(data[:remaining])
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
func BenchmarkGenerator1Byte(b *testing.B) {
	g := NewGenerator(nil, []byte{0})
	data := make([]byte, 1)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		n, err := g.Read(data)
		if err != nil {
			b.Fatal(err)
		}
		if n != 1 {
			b.Fatalf("Failed to read")
		}
	}
}

// Reads 16 bytes at a time to bench overhead. Calculates the cost per byte.
func BenchmarkGenerator16Bytes(b *testing.B) {
	g := NewGenerator(nil, []byte{0})
	data := make([]byte, 16)
	count := 0
	b.ResetTimer()

	for count != b.N {
		chunk := 16
		if b.N-count < 16 {
			chunk = b.N - count
		}
		n, err := g.Read(data[:chunk])
		if err != nil {
			b.Fatal(err)
		}
		if n != chunk {
			b.Fatalf("Failed to read")
		}
		count += chunk
	}
}

func decodeString(str string) []byte {
	d, err := hex.DecodeString(str)
	if err != nil {
		panic("Invalid hex string")
	}
	return d
}

var key = decodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

// Benches large chunks throughput. Calculates the cost per byte.
func BenchmarkAESCTRLarge(b *testing.B) {
	c, err := aes.NewCipher(key)
	if err != nil {
		b.Fatal(err)
	}
	e := cipher.NewCTR(c, make([]byte, aes.BlockSize))
	data := make([]byte, b.N)
	b.ResetTimer()

	// Interestingly, Generator is faster than AES in CTR, because there is no
	// need to XOR the data.
	e.XORKeyStream(data, data)
}

// Reads 1 byte at a time to bench overhead. Calculates the cost per byte.
func BenchmarkAESCTR1Byte(b *testing.B) {
	c, err := aes.NewCipher(key)
	if err != nil {
		b.Fatal(err)
	}
	e := cipher.NewCTR(c, make([]byte, aes.BlockSize))
	data := make([]byte, 1)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		e.XORKeyStream(data, data)
	}
}

// Reads 16 bytes at a time to bench overhead. Calculates the cost per byte.
func BenchmarkAESCTR16Bytes(b *testing.B) {
	c, err := aes.NewCipher(key)
	if err != nil {
		b.Fatal(err)
	}
	e := cipher.NewCTR(c, make([]byte, aes.BlockSize))
	data := make([]byte, 16)
	count := 0
	b.ResetTimer()

	for count != b.N {
		chunk := 16
		if b.N-count < 16 {
			chunk = b.N - count
		}
		e.XORKeyStream(data[:chunk], data[:chunk])
		count += chunk
	}
}

// Reseeds the generator. Calculates the cost per reseed.
func BenchmarkGeneratorReseed(b *testing.B) {
	g := NewGenerator(nil, []byte{0})
	data := make([]byte, 16)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		g.Write(data)
	}
}
