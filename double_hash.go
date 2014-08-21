// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed under the Apache License, Version 2.0
// that can be found in the LICENSE file.

// All the pages (p.) references are to Cryptography Engineering, N. Ferguson,
// B. Schneier, T. Kohno, ISBN 978-0-470-47424-2.

package fortuna

import (
	"hash"
)

// Enough zeros for SHA-3.
var zeros = [256]byte{}

// DoubleHash runs SHAd-X as defined in p. 86, Definition 7.
// It firsts reset h's internal state, then write 0^b to it, then write
// all the input data. It pass the resulting hash back into it and return this
// digest.
func DoubleHash(h hash.Hash, data ...[]byte) []byte {
	h.Reset()
	// p. 85
	// Instead of h(m), we can use h(h(0^b || m)) as a hash function, and claim a
	// security level of only n/2 bits. Here b is the block length of the
	// underlying compression function, so 0^b || m equates to prepending the
	// message with an all zero block before hashing.
	// p. 86
	// SHAd-256 is just the function m-> SHA-256(SHA-256(0⁵¹² || m)), for example.
	b := h.BlockSize()
	if l, err := h.Write(zeros[:b]); l != b || err != nil {
		panic("Unexpected hash write failure")
	}
	for _, i := range data {
		if l, err := h.Write(i); l != len(i) || err != nil {
			panic("Unexpected hash write failure")
		}
	}
	dst := h.Sum(nil)

	// Rehash the data.
	h.Reset()
	if l, err := h.Write(dst); l != len(dst) || err != nil {
		panic("Unexpected hash write failure")
	}
	return h.Sum(nil)
}
