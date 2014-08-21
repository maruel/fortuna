#!/usr/bin/env python
# Copyright 2013 Marc-Antoine Ruel. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

"""Generates the test data for generator_test.go in generator.json.

The data is base64 encoded.
"""

import json
import os
import sys

import fortuna_generator

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


INPUTS = [
    "00",
    "000102030405060708",
]


def main():
  data = []
  for i in INPUTS:
    seed = i.decode('hex')
    g = fortuna_generator.Generator(seed)
    v = {
        'Input': seed.encode('base64'),
        'Expected': [],
    }
    # Ordering and the length matters.
    for i in (70, 10):
      v['Expected'].append(
          {
            'Len': i,
            'Expected': g.PseudoRandomData(i).encode('base64')
          })
    data.append(v)

  with open(os.path.join(BASE_DIR, 'generator.json'), 'wb') as f:
    json.dump(data, f, indent=2)


if __name__ == '__main__':
    sys.exit(main())
