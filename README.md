Fortuna cryptographic random number generator implementation in Go
------------------------------------------------------------------

Fortuna implements the fortuna cryptographic random number generator as designed
by Bruce Schneier and Niels Ferguson and described in Cryptography Engineering,
N.  Ferguson, B. Schneier, T. Kohno, ISBN 978-0-470-47424-2. It was implemented
by Marc-Antoine Ruel.

Fortuna is best used in a long living server like a web server, where a lot of
unpredictable events occurs and can be used to seed the accumulator. The
implementation uses SHA-256 and AES-256 as the primitives.

This package includes all the necessary implementation and a python generator
implementation for testing purposes.

[![GoDoc](https://godoc.org/github.com/maruel/fortuna?status.svg)](https://godoc.org/github.com/maruel/fortuna)
[![Build Status](https://travis-ci.org/maruel/fortuna.svg?branch=master)](https://travis-ci.org/maruel/fortuna)
[![Coverage Status](https://img.shields.io/coveralls/maruel/fortuna.svg)](https://coveralls.io/r/maruel/fortuna?branch=master)


References
==========

All the pages (p.) references are to
[Cryptography Engineering](https://www.schneier.com/book-ce.html), N. Ferguson,
B. Schneier, T. Kohno, ISBN 978-0-470-47424-2.

Chapter 9 of Cryptography Engineering is freely available at
https://www.schneier.com/fortuna.pdf.
