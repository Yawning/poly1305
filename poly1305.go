// poly1305.go: Poly1305 MAC.

// Package poly1305 is a Poly1305 MAC implementation.  It is different from the
// golang.org/x/crypto implementation in that it exports a hash.Hash interface
// to support incremental updates.
//
// The implementation is based on Andrew Moon's poly1305-donna-32, as it is
// the most performant variant implementatble in pure Go.
package poly1305

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"unsafe"
)

const (
	// KeySize is the Poly1305 key size in bytes.
	KeySize = 32

	// Size is the Poly1305 MAC size in bytes.
	Size = 16

	// BlockSize is the Poly1305 block size in bytes.
	BlockSize = 16
)

var (
	// ErrInvalidKeySize is the error returned when an invalid sized key is
	// encountered.
	ErrInvalidKeySize = errors.New("poly1305: invalid key size")

	// ErrInvalidMacSize is the error returned when an invalid sized MAC is
	// encountered.
	ErrInvalidMacSize = errors.New("poly1305: invalid mac size")

	// useUnsafe is set at package load time when the current CPU does not
	// require the byteswap operations.
	useUnsafe bool
)

// Poly1305 is an instance of the Poly1305 MAC algorithm.
type Poly1305 struct {
	r        [5]uint32
	h        [5]uint32
	pad      [4]uint32
	leftover int
	buffer   [BlockSize]byte
	final    bool
}

// Write adds more data to the running hash.  It never returns an error.
func (st *Poly1305) Write(p []byte) (n int, err error) {
	//
	// poly1305-donna.c:poly1305_update()
	//

	m := p
	bytes := len(m)

	// handle leftover
	if st.leftover > 0 {
		want := BlockSize - st.leftover
		if want > bytes {
			want = bytes
		}
		for i := 0; i < want; i++ {
			st.buffer[st.leftover+i] = m[i]
		}
		bytes -= want
		m = m[want:]
		st.leftover += want
		if st.leftover < BlockSize {
			return len(p), nil
		}
		st.blocks(st.buffer[:], BlockSize)
		st.leftover = 0
	}

	// process full blocks
	if bytes >= BlockSize {
		want := bytes & (^(BlockSize - 1))
		st.blocks(m, want)
		m = m[want:]
		bytes -= want
	}

	// store leftover
	if bytes > 0 {
		for i := 0; i < bytes; i++ {
			st.buffer[st.leftover+i] = m[i]
		}
		st.leftover += bytes
	}

	return len(p), nil
}

// Sum appends the current hash to b and returns the resulting slice.  It does
// not change the underlying hash state.
func (st *Poly1305) Sum(b []byte) []byte {
	var mac [Size]byte
	tmp := *st
	tmp.finish(&mac)
	return append(b, mac[:]...)
}

// Reset clears the internal hash state and panic()s, because calling this is a
// sign that the user is doing something unadvisable.
func (st *Poly1305) Reset() {
	st.Clear() // Obliterate the state before panic().

	// Poly1305 keys are one time use only.
	panic("poly1305: Reset() is not supported")
}

// Size returns the number of bytes Sum will return.
func (st *Poly1305) Size() int {
	return Size
}

// BlockSize returns the hash's underlying block size.
func (st *Poly1305) BlockSize() int {
	return BlockSize
}

// Init (re-)initializes the hash instance with a given key.
func (st *Poly1305) Init(key []byte) {
	if len(key) != KeySize {
		panic(ErrInvalidKeySize)
	}

	//
	// poly1305-donna-32.h:poly1305_init()
	//

	// r &= 0xffffffc0ffffffc0ffffffc0fffffff
	if useUnsafe {
		st.r[0] = *(*uint32)(unsafe.Pointer(&key[0])) & 0x3ffffff
		st.r[1] = (*(*uint32)(unsafe.Pointer(&key[3])) >> 2) & 0x3ffff03
		st.r[2] = (*(*uint32)(unsafe.Pointer(&key[6])) >> 4) & 0x3ffc0ff
		st.r[3] = (*(*uint32)(unsafe.Pointer(&key[9])) >> 6) & 0x3f03fff
		st.r[4] = (*(*uint32)(unsafe.Pointer(&key[12])) >> 8) & 0x00fffff
	} else {
		st.r[0] = binary.LittleEndian.Uint32(key[0:]) & 0x3ffffff
		st.r[1] = (binary.LittleEndian.Uint32(key[3:]) >> 2) & 0x3ffff03
		st.r[2] = (binary.LittleEndian.Uint32(key[6:]) >> 4) & 0x3ffc0ff
		st.r[3] = (binary.LittleEndian.Uint32(key[9:]) >> 6) & 0x3f03fff
		st.r[4] = (binary.LittleEndian.Uint32(key[12:]) >> 8) & 0x00fffff
	}

	// h = 0
	for i := range st.h {
		st.h[i] = 0
	}

	// save pad for later
	if useUnsafe {
		padArr := (*[4]uint32)(unsafe.Pointer(&key[16]))
		st.pad[0] = padArr[0]
		st.pad[1] = padArr[1]
		st.pad[2] = padArr[2]
		st.pad[3] = padArr[3]
	} else {
		st.pad[0] = binary.LittleEndian.Uint32(key[16:])
		st.pad[1] = binary.LittleEndian.Uint32(key[20:])
		st.pad[2] = binary.LittleEndian.Uint32(key[24:])
		st.pad[3] = binary.LittleEndian.Uint32(key[28:])
	}

	st.leftover = 0
	st.final = false
}

// Clear purges the sensitive material in hash's internal state.
func (st *Poly1305) Clear() {
	for i := range st.h {
		st.h[i] = 0
	}
	for i := range st.r {
		st.r[i] = 0
	}
	for i := range st.pad {
		st.pad[i] = 0
	}
}

func (st *Poly1305) blocks(m []byte, bytes int) {
	//
	// poly1305-donna-32.h:poly1305_blocks()
	//

	var hibit uint32
	var d0, d1, d2, d3, d4 uint64
	var c uint32
	if !st.final {
		hibit = 1 << 24 // 1 << 128
	}
	r0, r1, r2, r3, r4 := st.r[0], st.r[1], st.r[2], st.r[3], st.r[4]
	s1, s2, s3, s4 := r1*5, r2*5, r3*5, r4*5
	h0, h1, h2, h3, h4 := st.h[0], st.h[1], st.h[2], st.h[3], st.h[4]

	for bytes >= BlockSize {
		// h += m[i]
		if useUnsafe {
			h0 += *(*uint32)(unsafe.Pointer(&m[0])) & 0x3ffffff
			h1 += (*(*uint32)(unsafe.Pointer(&m[3])) >> 2) & 0x3ffffff
			h2 += (*(*uint32)(unsafe.Pointer(&m[6])) >> 4) & 0x3ffffff
			h3 += (*(*uint32)(unsafe.Pointer(&m[9])) >> 6) & 0x3ffffff
			h4 += (*(*uint32)(unsafe.Pointer(&m[12])) >> 8) | hibit
		} else {
			h0 += binary.LittleEndian.Uint32(m[0:]) & 0x3ffffff
			h1 += (binary.LittleEndian.Uint32(m[3:]) >> 2) & 0x3ffffff
			h2 += (binary.LittleEndian.Uint32(m[6:]) >> 4) & 0x3ffffff
			h3 += (binary.LittleEndian.Uint32(m[9:]) >> 6) & 0x3ffffff
			h4 += (binary.LittleEndian.Uint32(m[12:]) >> 8) | hibit
		}

		// h *= r
		d0 = (uint64(h0) * uint64(r0)) + (uint64(h1) * uint64(s4)) + (uint64(h2) * uint64(s3)) + (uint64(h3) * uint64(s2)) + (uint64(h4) * uint64(s1))
		d1 = (uint64(h0) * uint64(r1)) + (uint64(h1) * uint64(r0)) + (uint64(h2) * uint64(s4)) + (uint64(h3) * uint64(s3)) + (uint64(h4) * uint64(s2))
		d2 = (uint64(h0) * uint64(r2)) + (uint64(h1) * uint64(r1)) + (uint64(h2) * uint64(r0)) + (uint64(h3) * uint64(s4)) + (uint64(h4) * uint64(s3))
		d3 = (uint64(h0) * uint64(r3)) + (uint64(h1) * uint64(r2)) + (uint64(h2) * uint64(r1)) + (uint64(h3) * uint64(r0)) + (uint64(h4) * uint64(s4))
		d4 = (uint64(h0) * uint64(r4)) + (uint64(h1) * uint64(r3)) + (uint64(h2) * uint64(r2)) + (uint64(h3) * uint64(r1)) + (uint64(h4) * uint64(r0))

		// (partial) h %= p
		c = uint32(d0 >> 26)
		h0 = uint32(d0) & 0x3ffffff

		d1 += uint64(c)
		c = uint32(d1 >> 26)
		h1 = uint32(d1) & 0x3ffffff

		d2 += uint64(c)
		c = uint32(d2 >> 26)
		h2 = uint32(d2) & 0x3ffffff

		d3 += uint64(c)
		c = uint32(d3 >> 26)
		h3 = uint32(d3) & 0x3ffffff

		d4 += uint64(c)
		c = uint32(d4 >> 26)
		h4 = uint32(d4) & 0x3ffffff

		h0 += c * 5
		c = h0 >> 26
		h0 = h0 & 0x3ffffff

		h1 += c

		m = m[BlockSize:]
		bytes -= BlockSize
	}

	st.h[0], st.h[1], st.h[2], st.h[3], st.h[4] = h0, h1, h2, h3, h4
}

func (st *Poly1305) finish(mac *[Size]byte) {
	//
	// poly1305-donna-32.h:poly1305_finish()
	//

	var c uint32
	var g0, g1, g2, g3, g4 uint32
	var f uint64
	var mask uint32

	// process the remaining block
	if st.leftover > 0 {
		st.buffer[st.leftover] = 1
		for i := st.leftover + 1; i < BlockSize; i++ {
			st.buffer[i] = 0
		}
		st.final = true
		st.blocks(st.buffer[:], BlockSize)
	}

	// fully carry h
	h0, h1, h2, h3, h4 := st.h[0], st.h[1], st.h[2], st.h[3], st.h[4]
	c = h1 >> 26
	h1 &= 0x3ffffff

	h2 += c
	c = h2 >> 26
	h2 &= 0x3ffffff

	h3 += c
	c = h3 >> 26
	h3 &= 0x3ffffff

	h4 += c
	c = h4 >> 26
	h4 &= 0x3ffffff

	h0 += c * 5
	c = h0 >> 26
	h0 &= 0x3ffffff

	h1 += c

	// compute h + -p
	g0 = h0 + 5
	c = g0 >> 26
	g0 &= 0x3ffffff

	g1 = h1 + c
	c = g1 >> 26
	g1 &= 0x3ffffff

	g2 = h2 + c
	c = g2 >> 26
	g2 &= 0x3ffffff

	g3 = h3 + c
	c = g3 >> 26
	g3 &= 0x3ffffff

	g4 = h4 + c - (1 << 26)

	// select h if h < p, or h + -p if h >= p
	mask = (g4 >> ((4 * 8) - 1)) - 1
	g0 &= mask
	g1 &= mask
	g2 &= mask
	g3 &= mask
	g4 &= mask
	mask = ^mask
	h0 = (h0 & mask) | g0
	h1 = (h1 & mask) | g1
	h2 = (h2 & mask) | g2
	h3 = (h3 & mask) | g3
	h4 = (h4 & mask) | g4

	// h = h % (2^128)
	h0 = ((h0) | (h1 << 26)) & 0xffffffff
	h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff
	h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff
	h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff

	// mac = (h + pad) % (2^128)
	f = uint64(h0) + uint64(st.pad[0])
	h0 = uint32(f)

	f = uint64(h1) + uint64(st.pad[1]) + (f >> 32)
	h1 = uint32(f)

	f = uint64(h2) + uint64(st.pad[2]) + (f >> 32)
	h2 = uint32(f)

	f = uint64(h3) + uint64(st.pad[3]) + (f >> 32)
	h3 = uint32(f)

	if useUnsafe {
		macArr := (*[4]uint32)(unsafe.Pointer(&mac[0]))
		macArr[0] = h0
		macArr[1] = h1
		macArr[2] = h2
		macArr[3] = h3
	} else {
		binary.LittleEndian.PutUint32(mac[0:], h0)
		binary.LittleEndian.PutUint32(mac[4:], h1)
		binary.LittleEndian.PutUint32(mac[8:], h2)
		binary.LittleEndian.PutUint32(mac[12:], h3)
	}

	// zero out the state
	st.Clear()
}

// New returns a new Poly1305 instance keyed with the supplied key.
func New(key []byte) (*Poly1305, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	h := &Poly1305{}
	h.Init(key)
	return h, nil
}

// Sum does exactly what golang.org/x/crypto/poly1305.Sum() does.
func Sum(mac *[Size]byte, m []byte, key *[KeySize]byte) {
	var h Poly1305
	h.Init(key[:])
	h.Write(m)
	h.finish(mac)
}

// Verify does exactly what golang.org/x/crypto/poly1305.Verify does.
func Verify(mac *[Size]byte, m []byte, key *[KeySize]byte) bool {
	var m2 [Size]byte
	Sum(&m2, m, key)
	return subtle.ConstantTimeCompare(mac[:], m2[:]) == 1
}

func init() {
	// Use the UTF-32 (UCS-4) Byte Order Mark to detect host byte order,
	// which enables the further use of 'unsafe' to work around the Go
	// compiler's piss-poor inlining.  Gotta Go Fast.
	const bomLE = 0x0000feff
	bom := [4]byte{0xff, 0xfe, 0x00, 0x00}

	bomHost := *(*uint32)(unsafe.Pointer(&bom[0]))
	if bomHost == 0x0000feff { // Little endian, use unsafe.
		useUnsafe = true
	}
}

var _ hash.Hash = (*Poly1305)(nil)
