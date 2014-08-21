# Copyright 2013 Marc-Antoine Ruel. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

"""Implements SHAd256 and Fortuna's Generator class.

This is used to verify the go native implementation matches what is expected
from a different implementation.

In particular, the pycrypto implementation is not 'correct', it doesn't follow
the definition in the book.
"""

import hashlib
from Crypto.Cipher import AES


def sha_double(hash_class, data):
    """Implements the generic SHAd-NNN algorithm.

    Warning: https://www.dlitz.net/crypto/shad256-test-vectors/ is a top hit
    when searching for test vector but the author didn't implement the right
    algorithm, he skipped the 0^b prefix.

    ** Warning**
    In particular, the pycrypto implementation "SHAd256" is incorrect. Do not
    use it. The book clearly states multiple times that zero bytes must be
    preprended.
    """
    h = hash_class()
    h.update('\0' * h.block_size + data)
    return hash_class(h.digest()).digest()


def shad256(data):
    """Implements SHAd-256."""
    # pylint: disable=E1101
    return sha_double(hashlib.sha256, data)


def long_to_lsb_str(value):
    """Converts value to a LSB (little endian) string of 16 bytes."""
    c = [0] * 16
    i = 0
    while value:
        c[i] = value % 256L
        value /= 256L
        i += 1
    return ''.join(map(chr, c))


assert ('000102' + '00' * 13).decode('hex') == long_to_lsb_str(0x020100)


class Generator(object):
    """A complete Fortuna Generator implementation.

    It is hard-coded for AES-256 and SHAd-256.
    """
    def __init__(self, seed=None):
        """Effectively InitializeGenerator at p. 145."""
        self.key = '\x00' * 32
        self.counter = 0L
        if seed:
          self.Reseed(seed)

    def Reseed(self, seed):
        """p. 145."""
        self.key = shad256(self.key + seed)
        self.counter += 1L

    def PseudoRandomData(self, length):
        """Generates N bytes of PRNG data. p. 146."""
        assert 0 <= length <= (1 << 20)
        assert self.counter
        result = self._GenerateBlocks((length+15)/16)[:length]
        self.key = self._GenerateBlocks(2)
        return result

    def _GenerateBlocks(self, blocks):
        """Generates N blocks of PRNG data. p. 146."""
        result = []
        E = AES.new(self.key)
        for _ in xrange(blocks):
            # Generate 16 bytes at a time.
            result.append(E.encrypt(long_to_lsb_str(self.counter)))
            self.counter += 1L
        return ''.join(result)
