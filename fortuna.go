// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed under the Apache License, Version 2.0
// that can be found in the LICENSE file.

// Package fortuna implements the fortuna random number generator as designed
// by Bruce Schneier and Niels Ferguson and described in Cryptography
// Engineering, N. Ferguson, B. Schneier, T. Kohno, ISBN 978-0-470-47424-2.
//
// Fortuna is best used in a long living server like a http server, where a lot
// of unpredictable events occurs and can be used to seed the accumulator.
// Uses SHA-256 and AES-256 as the primitives.
package fortuna

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"sync"
	"time"
)

const (
	// Reseed must not done faster than this interval rate to ensure that even if
	// events are attacker-controlled, the attacker can't empty the entropy pools
	// to make the generator completely determinitic. See section 9.5.2 p.
	// 149-150.
	reseedInterval = 100 * time.Millisecond
	// Because of the way the pools are drained from their entropy, having 32
	// pools ensure that even at 10 reseeds per second, it will take more than 13
	// years before P32 would ever be used. See section 9.5.2 p. 149-150.
	numPools = 32
	// Do not reseed unless the pool has generated this amount of data.
	minPoolSize = sha256.BlockSize
)

// Fortuna implements a cryptographic random number generator. It is used as an
// randomness entropy pool. Randomness can be read from and entropy can be
// added via AddRandomEvent().
type Fortuna interface {
	io.Reader

	// AddRandomEvent adds random data (entropy) from the given source. data
	// should be in general 32 bytes or less. It is not useful to add more than
	// 32 bytes of entropy at a time. If the data is more than 32 bytes, it will
	// hashed first.
	AddRandomEvent(source byte, data []byte)
}

// countedHash is a hash object that keeps track of the amount of data that was
// written to it.
//
// This object is not thread-safe.
type countedHash struct {
	hash.Hash
	length int
}

func (p *countedHash) Write(data []byte) (int, error) {
	p.length += len(data)
	return p.Hash.Write(data)
}

func (p *countedHash) Reset() {
	p.Hash.Reset()
	p.length = 0
}

// Accumulator
//
// An accumulator stores entropy distributed in multiple pools. It
// contains the generator that is used as the PRNG. It is the main fortuna
// component.
type accumulator struct {
	lock       sync.Mutex
	numReseed  int                              // Determines which entropy pools are used at the next reseeding
	nextPool   int                              // Next pool that should be used to add randomness from an external source
	lastReseed time.Time                        // Last time seeding was done
	generator  generator                        // PRNG source, a rolling AES-256 in CTR mode
	pools      [numPools]countedHash            // Entropy pools
	temp       [numPools / 8 * sha256.Size]byte // Scratch space used in reseed to save a memory allocation.
}

func (a *accumulator) prepare() {
	now := time.Now()
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.lastReseed.After(now) {
		// Clock rewinded. Reset lastReseed so the reseed will occur as soon as
		// possible.
		a.lastReseed = time.Time{}
	}
	// Only reseed when enough entropy accumulated and a minimum interval occured
	// since the last reseed.
	if a.pools[0].length >= minPoolSize && now.After(a.lastReseed.Add(reseedInterval)) {
		a.reseed(now)
	}
}

// Read reads random data up to 1Mb, reseeding the accumulator if necessary.
func (a *accumulator) Read(data []byte) (int, error) {
	a.prepare()
	// Return PRNG data from the generator. The generator is thread-safe so no
	// need to keep the accumulator lock.
	return a.generator.Read(data)
}

// reseed uses entropy from the pools to reseed the generator.
// It records now as the time of the reseed.
//
// This method must be called with the lock held.
func (a *accumulator) reseed(now time.Time) {
	// Seeding happens at a minimum interval of reseedInterval so it's not a perf
	// critical.
	a.lastReseed = now
	a.numReseed++
	seed := a.temp[:0]

	mask := 0
	// Pool P_i is included if 2**i is a divisor of a.numReseed
	for i := 0; i < numPools && a.numReseed&mask == 0; i++ {
		seed = a.pools[i].Sum(seed)
		// Reset the entropy pool after extracting entropy from it so this
		// entropy is not used again.
		a.pools[i].Reset()
		mask <<= 1
		mask |= 1
	}

	// Double SHA256 the key plus the seed. In practice, the sum is at least
	// minPoolSize.
	_, _ = a.generator.Write(seed)
}

func (a *accumulator) AddRandomEvent(source byte, data []byte) {
	// This function must return very quickly so the data is first copied and the
	// actual processing is done in a goroutine. This removes the potential
	// undesired serialization of the caller due to the accumulator's lock.
	var buffer []byte
	if len(data) > 32 {
		h := sha1.New()
		_, _ = h.Write(data)
		buffer = h.Sum(make([]byte, 2, 2+h.Size()))
	} else {
		buffer = append(make([]byte, 2, len(data)+2), data...)
	}
	buffer[0] = source
	buffer[1] = byte(len(data))

	go func() {
		a.lock.Lock()
		defer a.lock.Unlock()

		_, _ = a.pools[a.nextPool].Write(buffer)
		a.nextPool = (a.nextPool + 1) % numPools
	}()
}

// NewFortuna returns a new Fortuna instance seeded using seed.
// It is up to the caller to ensure that enough entropy is added to it. The
// io.Reader interface is to be used to read random data.
//
// The resulting object is thread safe.
func NewFortuna(seed []byte) (Fortuna, error) {
	// Described as InitializePRNG p.153
	//
	// 2*minPoolSize guarantees that the first pool is correctly initialized and
	// the remaining ones have at least a little bit of entropy.
	if len(seed) < 2*minPoolSize {
		return nil, fmt.Errorf("initial seed is too short, provide at least %d bytes", 2*minPoolSize)
	}
	a := &accumulator{
		generator: newGenerator(nil, nil),
	}
	for i := range a.pools {
		a.pools[i].Hash = sha256.New()
	}

	// Write the initial minPoolSize bytes to pool 0, otherwise the generator
	// will not be correctly reseeded on the initial accumulator.Read() is called.
	// Writes the timestamp to pool 0. This means only 64-16 = 48 bytes of the
	// seed are used in the initial key. The rest of the seed is distributed
	// across the remaining entropy pools.
	pool0 := [minPoolSize]byte{}
	// Fill the remaining of pool0 with the first part of seed.
	copy(pool0[16:], seed)
	a.AddRandomEvent(0, pool0[:])

	// Distribute the remaining seed across the remaining pools.
	seed = seed[minPoolSize+16:]
	// When len(seed)%(numPools-1) != 0, distributes more bytes to the first
	// pools.
	for i := 1; i < numPools; i++ {
		remaining := numPools - i
		perPool := (len(seed) + remaining - 1) / remaining
		a.AddRandomEvent(byte(i), seed[:perPool])
		seed = seed[perPool:]
	}
	// It's now safe to reseed the generator. This adds a very minimalist amount
	// of non-determinism in the accumulator. This is not sufficient for a
	// crypto-level RNG.
	a.lock.Lock()
	defer a.lock.Unlock()
	a.reseed(time.Now())
	return a, nil
}
