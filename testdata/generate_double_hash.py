#!/usr/bin/env python
# Copyright 2013 Marc-Antoine Ruel. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

"""Generates the test data for double_hash_test.go in double_hash.json.

The data is base64 encoded.
"""

import json
import os
import sys

import fortuna_generator

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


INPUTS = [
    '',
    'abc',
    ('de188941a3375d3a8a061e67576e926dc71a7fa3f0cceb97452b4d3227965f9ea8cc7507'
     '6d9fb9c5417aa5cb30fc22198b34982dbb629e').decode('hex'),
]


def main():
  data = [
      {
        'Input': i.encode('base64'),
        'Expected': fortuna_generator.shad256(i).encode('base64'),
      } for i in INPUTS
  ]
  with open(os.path.join(BASE_DIR, 'double_hash.json'), 'wb') as f:
    json.dump(data, f, indent=2)


if __name__ == '__main__':
  sys.exit(main())
