### poly1305: Go Poly1305
#### Yawning Angel (yawning at schwanenlied dot me)

Poly1305 implements the Poly1305 MAC algorithm, exposing a saner interface than
the one provided by golang.org/x/crypto/poly1305.  In particular it exposes a
hash.Hash.

The implementation is based on the Public Domain poly1305-donna-32 by Andrew
Moon (poly1305-donna-64 would be faster but Go doesn't have 128 bit integer
math).

| Implementation       | 64 byte      | 1024 byte   |
| -------------------- | ------------ | ----------- |
| go.crypto (ref)      | 94.51 MB/s   | 187.67 MB/s |
| go.crypto (amd64)    | 540.68 MB/s  | 909.97 MB/s |
| go poly1305-donna-32 | 231.92 MB/s  | 433.34 MB/s |

Note: All numbers on a i5-4250U, and to be taken with a huge grain of salt.
