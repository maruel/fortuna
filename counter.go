// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed under the Apache License, Version 2.0
// that can be found in the LICENSE file.

package fortuna

// Little Endian counter.
type counter []byte

// incr adds 1 to c by treating it as a little endian big int.
func (c counter) incr() {
	for i := range c {
		c[i] += 1
		if c[i] != 0 {
			return
		}
	}
	// The value overflowed.
	for i := range c {
		c[i] = 0
	}
}
