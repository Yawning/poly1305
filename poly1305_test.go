package poly1305

import (
	"bytes"
	"testing"
)

// Shamelessly stolen from poly1305-donna.c:poly1305_power_on_self_test()

func TestNaCl(t *testing.T) {
	var naclKey = []byte{
		0xee, 0xa6, 0xa7, 0x25, 0x1c, 0x1e, 0x72, 0x91,
		0x6d, 0x11, 0xc2, 0xcb, 0x21, 0x4d, 0x3c, 0x25,
		0x25, 0x39, 0x12, 0x1d, 0x8e, 0x23, 0x4e, 0x65,
		0x2d, 0x65, 0x1f, 0xa4, 0xc8, 0xcf, 0xf8, 0x80,
	}

	var naclMsg = []byte{
		0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73,
		0xc2, 0x96, 0x50, 0xba, 0x32, 0xfc, 0x76, 0xce,
		0x48, 0x33, 0x2e, 0xa7, 0x16, 0x4d, 0x96, 0xa4,
		0x47, 0x6f, 0xb8, 0xc5, 0x31, 0xa1, 0x18, 0x6a,
		0xc0, 0xdf, 0xc1, 0x7c, 0x98, 0xdc, 0xe8, 0x7b,
		0x4d, 0xa7, 0xf0, 0x11, 0xec, 0x48, 0xc9, 0x72,
		0x71, 0xd2, 0xc2, 0x0f, 0x9b, 0x92, 0x8f, 0xe2,
		0x27, 0x0d, 0x6f, 0xb8, 0x63, 0xd5, 0x17, 0x38,
		0xb4, 0x8e, 0xee, 0xe3, 0x14, 0xa7, 0xcc, 0x8a,
		0xb9, 0x32, 0x16, 0x45, 0x48, 0xe5, 0x26, 0xae,
		0x90, 0x22, 0x43, 0x68, 0x51, 0x7a, 0xcf, 0xea,
		0xbd, 0x6b, 0xb3, 0x73, 0x2b, 0xc0, 0xe9, 0xda,
		0x99, 0x83, 0x2b, 0x61, 0xca, 0x01, 0xb6, 0xde,
		0x56, 0x24, 0x4a, 0x9e, 0x88, 0xd5, 0xf9, 0xb3,
		0x79, 0x73, 0xf6, 0x22, 0xa4, 0x3d, 0x14, 0xa6,
		0x59, 0x9b, 0x1f, 0x65, 0x4c, 0xb4, 0x5a, 0x74,
		0xe3, 0x55, 0xa5,
	}

	var naclMac = []byte{
		0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5,
		0x2a, 0x7d, 0xfb, 0x4b, 0x3d, 0x33, 0x05, 0xd9,
	}

	// Oneshot
	h, err := New(naclKey[:])
	if err != nil {
		t.Fatal(err)
	}

	n, err := h.Write(naclMsg[:])
	if err != nil {
		t.Fatal(err)
	} else if n != len(naclMsg) {
		t.Fatalf("h.Write() returned unexpected length: %d", n)
	}

	mac := h.Sum(nil)
	if !bytes.Equal(mac, naclMac[:]) {
		t.Fatalf("mac != naclMac")
	}

	// Incremental
	h, err = New(naclKey[:])
	if err != nil {
		t.Fatal(err)
	}

	for i, s := range []struct{ off, sz int }{
		{0, 32},
		{32, 64},
		{96, 16},
		{112, 8},
		{120, 4},
		{124, 2},
		{126, 1},
		{127, 1},
		{128, 1},
		{129, 1},
		{130, 1},
	} {
		n, err := h.Write(naclMsg[s.off : s.off+s.sz])
		if err != nil {
			t.Fatalf("[%d]: h.Write(): %s", i, err)
		} else if n != s.sz {
			t.Fatalf("[%d]: h.Write(): %d (expected: %d)", i, n, s.sz)
		}
	}

	mac = h.Sum(nil)
	if !bytes.Equal(mac, naclMac[:]) {
		t.Fatalf("mac != naclMac")
	}
}

func TestWrap(t *testing.T) {
	// generates a final value of (2^130 - 2) == 3
	wrapKey := [KeySize]byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	wrapMsg := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}

	wrapMac := [Size]byte{
		0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	var mac [Size]byte
	Sum(&mac, wrapMsg, &wrapKey)
	if !bytes.Equal(mac[:], wrapMac[:]) {
		t.Fatalf("mac != wrapMac")
	}
}

func TestTotal(t *testing.T) {
	// mac of the macs of messages of length 0 to 256, where the key and messages
	// have all their values set to the length
	totalKey := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x00,
	}

	totalMac := []byte{
		0x64, 0xaf, 0xe2, 0xe8, 0xd6, 0xad, 0x7b, 0xbd,
		0xd2, 0x87, 0xf9, 0x7c, 0x44, 0x62, 0x3d, 0x39,
	}

	var allKey [KeySize]byte
	allMsg := make([]byte, 256)

	totalCtx, err := New(totalKey[:])
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 256; i++ {
		// set key and message to 'i,i,i..'
		for j := range allKey {
			allKey[j] = byte(i)
		}
		for j := 0; j < i; j++ {
			allMsg[j] = byte(i)
		}

		var mac [Size]byte
		Sum(&mac, allMsg[:i], &allKey)
		n, err := totalCtx.Write(mac[:])
		if err != nil {
			t.Fatalf("[%d]: h.Write(): %s", i, err)
		} else if n != len(mac) {
			t.Fatalf("[%d]: h.Write(): %d (expected: %d)", i, n, len(mac))
		}
	}
	mac := totalCtx.Sum(nil)
	if !bytes.Equal(mac, totalMac[:]) {
		t.Fatalf("mac != totalMac")
	}
}

func TestIETFDraft(t *testing.T) {
	// Test vectors taken from:
	// https://www.ietf.org/id/draft-irtf-cfrg-chacha20-poly1305-07.txt

	vectors := []struct {
		key [KeySize]byte
		m   []byte
		tag [Size]byte
	}{
		// Test Vector #1
		{
			[KeySize]byte{},
			[]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			[Size]byte{},
		},

		// Test Vector #2
		{
			[KeySize]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70,
				0xf0, 0xef, 0xca, 0x96, 0x22, 0x7a, 0x86, 0x3e,
			},
			[]byte{
				0x41, 0x6e, 0x79, 0x20, 0x73, 0x75, 0x62, 0x6d,
				0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x74,
				0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x49, 0x45,
				0x54, 0x46, 0x20, 0x69, 0x6e, 0x74, 0x65, 0x6e,
				0x64, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x74,
				0x68, 0x65, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x72,
				0x69, 0x62, 0x75, 0x74, 0x6f, 0x72, 0x20, 0x66,
				0x6f, 0x72, 0x20, 0x70, 0x75, 0x62, 0x6c, 0x69,
				0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x61,
				0x73, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x6f, 0x72,
				0x20, 0x70, 0x61, 0x72, 0x74, 0x20, 0x6f, 0x66,
				0x20, 0x61, 0x6e, 0x20, 0x49, 0x45, 0x54, 0x46,
				0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65,
				0x74, 0x2d, 0x44, 0x72, 0x61, 0x66, 0x74, 0x20,
				0x6f, 0x72, 0x20, 0x52, 0x46, 0x43, 0x20, 0x61,
				0x6e, 0x64, 0x20, 0x61, 0x6e, 0x79, 0x20, 0x73,
				0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74,
				0x20, 0x6d, 0x61, 0x64, 0x65, 0x20, 0x77, 0x69,
				0x74, 0x68, 0x69, 0x6e, 0x20, 0x74, 0x68, 0x65,
				0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74,
				0x20, 0x6f, 0x66, 0x20, 0x61, 0x6e, 0x20, 0x49,
				0x45, 0x54, 0x46, 0x20, 0x61, 0x63, 0x74, 0x69,
				0x76, 0x69, 0x74, 0x79, 0x20, 0x69, 0x73, 0x20,
				0x63, 0x6f, 0x6e, 0x73, 0x69, 0x64, 0x65, 0x72,
				0x65, 0x64, 0x20, 0x61, 0x6e, 0x20, 0x22, 0x49,
				0x45, 0x54, 0x46, 0x20, 0x43, 0x6f, 0x6e, 0x74,
				0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e,
				0x22, 0x2e, 0x20, 0x53, 0x75, 0x63, 0x68, 0x20,
				0x73, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e,
				0x74, 0x73, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75,
				0x64, 0x65, 0x20, 0x6f, 0x72, 0x61, 0x6c, 0x20,
				0x73, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e,
				0x74, 0x73, 0x20, 0x69, 0x6e, 0x20, 0x49, 0x45,
				0x54, 0x46, 0x20, 0x73, 0x65, 0x73, 0x73, 0x69,
				0x6f, 0x6e, 0x73, 0x2c, 0x20, 0x61, 0x73, 0x20,
				0x77, 0x65, 0x6c, 0x6c, 0x20, 0x61, 0x73, 0x20,
				0x77, 0x72, 0x69, 0x74, 0x74, 0x65, 0x6e, 0x20,
				0x61, 0x6e, 0x64, 0x20, 0x65, 0x6c, 0x65, 0x63,
				0x74, 0x72, 0x6f, 0x6e, 0x69, 0x63, 0x20, 0x63,
				0x6f, 0x6d, 0x6d, 0x75, 0x6e, 0x69, 0x63, 0x61,
				0x74, 0x69, 0x6f, 0x6e, 0x73, 0x20, 0x6d, 0x61,
				0x64, 0x65, 0x20, 0x61, 0x74, 0x20, 0x61, 0x6e,
				0x79, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20, 0x6f,
				0x72, 0x20, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x2c,
				0x20, 0x77, 0x68, 0x69, 0x63, 0x68, 0x20, 0x61,
				0x72, 0x65, 0x20, 0x61, 0x64, 0x64, 0x72, 0x65,
				0x73, 0x73, 0x65, 0x64, 0x20, 0x74, 0x6f,
			},
			[Size]byte{
				0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70,
				0xf0, 0xef, 0xca, 0x96, 0x22, 0x7a, 0x86, 0x3e,
			},
		},

		// Test Vector #3
		{
			[KeySize]byte{
				0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70,
				0xf0, 0xef, 0xca, 0x96, 0x22, 0x7a, 0x86, 0x3e,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			[]byte{
				0x41, 0x6e, 0x79, 0x20, 0x73, 0x75, 0x62, 0x6d,
				0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x74,
				0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x49, 0x45,
				0x54, 0x46, 0x20, 0x69, 0x6e, 0x74, 0x65, 0x6e,
				0x64, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x74,
				0x68, 0x65, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x72,
				0x69, 0x62, 0x75, 0x74, 0x6f, 0x72, 0x20, 0x66,
				0x6f, 0x72, 0x20, 0x70, 0x75, 0x62, 0x6c, 0x69,
				0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x61,
				0x73, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x6f, 0x72,
				0x20, 0x70, 0x61, 0x72, 0x74, 0x20, 0x6f, 0x66,
				0x20, 0x61, 0x6e, 0x20, 0x49, 0x45, 0x54, 0x46,
				0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65,
				0x74, 0x2d, 0x44, 0x72, 0x61, 0x66, 0x74, 0x20,
				0x6f, 0x72, 0x20, 0x52, 0x46, 0x43, 0x20, 0x61,
				0x6e, 0x64, 0x20, 0x61, 0x6e, 0x79, 0x20, 0x73,
				0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74,
				0x20, 0x6d, 0x61, 0x64, 0x65, 0x20, 0x77, 0x69,
				0x74, 0x68, 0x69, 0x6e, 0x20, 0x74, 0x68, 0x65,
				0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74,
				0x20, 0x6f, 0x66, 0x20, 0x61, 0x6e, 0x20, 0x49,
				0x45, 0x54, 0x46, 0x20, 0x61, 0x63, 0x74, 0x69,
				0x76, 0x69, 0x74, 0x79, 0x20, 0x69, 0x73, 0x20,
				0x63, 0x6f, 0x6e, 0x73, 0x69, 0x64, 0x65, 0x72,
				0x65, 0x64, 0x20, 0x61, 0x6e, 0x20, 0x22, 0x49,
				0x45, 0x54, 0x46, 0x20, 0x43, 0x6f, 0x6e, 0x74,
				0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e,
				0x22, 0x2e, 0x20, 0x53, 0x75, 0x63, 0x68, 0x20,
				0x73, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e,
				0x74, 0x73, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75,
				0x64, 0x65, 0x20, 0x6f, 0x72, 0x61, 0x6c, 0x20,
				0x73, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e,
				0x74, 0x73, 0x20, 0x69, 0x6e, 0x20, 0x49, 0x45,
				0x54, 0x46, 0x20, 0x73, 0x65, 0x73, 0x73, 0x69,
				0x6f, 0x6e, 0x73, 0x2c, 0x20, 0x61, 0x73, 0x20,
				0x77, 0x65, 0x6c, 0x6c, 0x20, 0x61, 0x73, 0x20,
				0x77, 0x72, 0x69, 0x74, 0x74, 0x65, 0x6e, 0x20,
				0x61, 0x6e, 0x64, 0x20, 0x65, 0x6c, 0x65, 0x63,
				0x74, 0x72, 0x6f, 0x6e, 0x69, 0x63, 0x20, 0x63,
				0x6f, 0x6d, 0x6d, 0x75, 0x6e, 0x69, 0x63, 0x61,
				0x74, 0x69, 0x6f, 0x6e, 0x73, 0x20, 0x6d, 0x61,
				0x64, 0x65, 0x20, 0x61, 0x74, 0x20, 0x61, 0x6e,
				0x79, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20, 0x6f,
				0x72, 0x20, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x2c,
				0x20, 0x77, 0x68, 0x69, 0x63, 0x68, 0x20, 0x61,
				0x72, 0x65, 0x20, 0x61, 0x64, 0x64, 0x72, 0x65,
				0x73, 0x73, 0x65, 0x64, 0x20, 0x74, 0x6f,
			},
			[Size]byte{
				0xf3, 0x47, 0x7e, 0x7c, 0xd9, 0x54, 0x17, 0xaf,
				0x89, 0xa6, 0xb8, 0x79, 0x4c, 0x31, 0x0c, 0xf0,
			},
		},

		// Test Vector #4
		{
			[KeySize]byte{
				0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a,
				0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
				0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09,
				0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
			},
			[]byte{
				0x27, 0x54, 0x77, 0x61, 0x73, 0x20, 0x62, 0x72,
				0x69, 0x6c, 0x6c, 0x69, 0x67, 0x2c, 0x20, 0x61,
				0x6e, 0x64, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
				0x6c, 0x69, 0x74, 0x68, 0x79, 0x20, 0x74, 0x6f,
				0x76, 0x65, 0x73, 0x0a, 0x44, 0x69, 0x64, 0x20,
				0x67, 0x79, 0x72, 0x65, 0x20, 0x61, 0x6e, 0x64,
				0x20, 0x67, 0x69, 0x6d, 0x62, 0x6c, 0x65, 0x20,
				0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x77,
				0x61, 0x62, 0x65, 0x3a, 0x0a, 0x41, 0x6c, 0x6c,
				0x20, 0x6d, 0x69, 0x6d, 0x73, 0x79, 0x20, 0x77,
				0x65, 0x72, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20,
				0x62, 0x6f, 0x72, 0x6f, 0x67, 0x6f, 0x76, 0x65,
				0x73, 0x2c, 0x0a, 0x41, 0x6e, 0x64, 0x20, 0x74,
				0x68, 0x65, 0x20, 0x6d, 0x6f, 0x6d, 0x65, 0x20,
				0x72, 0x61, 0x74, 0x68, 0x73, 0x20, 0x6f, 0x75,
				0x74, 0x67, 0x72, 0x61, 0x62, 0x65, 0x2e,
			},
			[Size]byte{
				0x45, 0x41, 0x66, 0x9a, 0x7e, 0xaa, 0xee, 0x61,
				0xe7, 0x08, 0xdc, 0x7c, 0xbc, 0xc5, 0xeb, 0x62,
			},
		},

		// Test Vector #5
		//
		// If one uses 130-bit partial reduction, does the code handle the case
		// where partially reduced final result is not fully reduced?
		{
			[KeySize]byte{
				// R
				0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// S
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			[]byte{
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			},
			[Size]byte{
				0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},

		// Test Vector #6
		//
		// What happens if addition of s overflows modulo 2^128?
		{
			[KeySize]byte{
				// R
				0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// S
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			},
			[]byte{
				0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			[Size]byte{
				0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},

		// Test Vector #7
		//
		// What happens if data limb is all ones and there is carry from lower
		// limb?
		{
			[KeySize]byte{
				// R
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// S
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			[]byte{
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			[Size]byte{
				0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},

		// Test Vector #8
		//
		// What happens if final result from polynomial part is exactly
		// 2^130-5?
		{
			[KeySize]byte{
				// R
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// S
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			[]byte{
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFB, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE,
				0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE,
				0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
			},
			[Size]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},

		// Test Vector #9
		//
		// What happens if final result from polynomial part is exactly
		// 2^130-6?
		{
			[KeySize]byte{
				// R
				0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// S
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			[]byte{
				0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			},
			[Size]byte{
				0xFA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			},
		},

		// Test Vector #10
		//
		// What happens if 5*H+L-type reduction produces 131-bit intermediate
		// result?
		{
			[KeySize]byte{
				// R
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// S
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			[]byte{
				0xE3, 0x35, 0x94, 0xD7, 0x50, 0x5E, 0x43, 0xB9,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x33, 0x94, 0xD7, 0x50, 0x5E, 0x43, 0x79, 0xCD,
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			[Size]byte{
				0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},

		// Test Vector #11
		//
		// What happens if 5*H+L-type reduction produces 131-bit final result?
		{
			[KeySize]byte{
				// R
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// S
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			[]byte{
				0xE3, 0x35, 0x94, 0xD7, 0x50, 0x5E, 0x43, 0xB9,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x33, 0x94, 0xD7, 0x50, 0x5E, 0x43, 0x79, 0xCD,
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			[Size]byte{
				0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
	}

	for i, vec := range vectors {
		var mac [Size]byte
		Sum(&mac, vec.m, &vec.key)
		if !bytes.Equal(mac[:], vec.tag[:]) {
			t.Errorf("[%d]: mac != vec.tag", i)
		}
		if !Verify(&vec.tag, vec.m, &vec.key) {
			t.Errorf("[%d]: Verify(tag, m, key) returned false", i)
		}
	}
}

func TestIETFDraftForceByteswap(t *testing.T) {
	if !useUnsafe {
		t.Skipf("not little endian, slow path already taken")
	} else {
		useUnsafe = false
		TestIETFDraft(t)
		useUnsafe = true
	}
}

// Swiped from golang.org/x/crypto/poly1305/poly1305_test.go.

func Benchmark64(b *testing.B) {
	b.StopTimer()
	var mac [Size]byte
	var key [KeySize]byte
	m := make([]byte, 64)
	b.SetBytes(int64(len(m)))
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		Sum(&mac, m, &key)
	}
}

func Benchmark1k(b *testing.B) {
	b.StopTimer()
	var mac [Size]byte
	var key [KeySize]byte
	m := make([]byte, 1024)
	b.SetBytes(int64(len(m)))
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		Sum(&mac, m, &key)
	}
}
