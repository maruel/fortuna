// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed under the Apache License, Version 2.0
// that can be found in the LICENSE file.

package fortuna

import (
	"bytes"
	"testing"
)

var counterTestData = [][2]counter{
	{[]byte{0}, []byte{1}},
	{[]byte{1}, []byte{2}},
	{[]byte{255}, []byte{0}},
	{[]byte{0, 0}, []byte{1, 0}},
	{[]byte{1, 0}, []byte{2, 0}},
	{[]byte{255, 0}, []byte{0, 1}},
	{[]byte{255, 1}, []byte{0, 2}},
	{[]byte{255, 255}, []byte{0, 0}},
	{[]byte{255, 255, 0}, []byte{0, 0, 1}},
}

func TestCounter(t *testing.T) {
	for _, i := range counterTestData {
		input := i[0]
		expected := i[1]
		actual := make(counter, len(input))
		copy(actual, input)
		actual.incr()
		if !bytes.Equal(actual, expected) {
			t.Fatalf("%v + 1 == %v != %v", input, actual, expected)
		}
	}
}
