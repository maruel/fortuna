// Copyright 2013 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed under the Apache License, Version 2.0
// that can be found in the LICENSE file.

package fortuna

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"testing"
)

type sha256dTestData struct {
	Input    []byte
	Expected []byte
}

func loadSHA256dTestData(t *testing.T, name string) []sha256dTestData {
	content, err := ioutil.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var data []sha256dTestData
	if err = json.Unmarshal(content, &data); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDoubleHash(t *testing.T) {
	t.Parallel()
	for i, v := range loadSHA256dTestData(t, "double_hash.json") {
		actual := DoubleHash(sha256.New(), v.Input)
		if 0 != bytes.Compare(actual, v.Expected) {
			t.Fatalf("Index %d; SHA256d(%v) -> %v != %v", i, v.Input, v.Expected, actual)
		}
	}
}
