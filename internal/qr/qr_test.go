package qr

import (
	"bytes"
	"errors"
	"testing"
)

// Reed-Solomon vector for version 1-M "HELLO WORLD" from the Thonky QR tutorial.
func TestRSRemainder(t *testing.T) {
	data := []byte{32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17}
	want := []byte{196, 35, 39, 119, 235, 215, 231, 226, 93, 23}
	if got := rsRemainder(data, rsDivisor(10)); !bytes.Equal(got, want) {
		t.Errorf("rsRemainder = %v, want %v", got, want)
	}
}

func TestEncodeVersionSelection(t *testing.T) {
	for _, tc := range []struct{ n, size int }{
		{14, 21},  // v1-M holds 14 bytes
		{15, 25},  // spills into v2
		{213, 57}, // v10-M maximum
	} {
		c, err := Encode(bytes.Repeat([]byte{'a'}, tc.n))
		if err != nil {
			t.Fatalf("Encode(%d bytes): %v", tc.n, err)
		}
		if c.Size != tc.size {
			t.Errorf("Encode(%d bytes) size = %d, want %d", tc.n, c.Size, tc.size)
		}
	}
	if _, err := Encode(make([]byte, 214)); !errors.Is(err, ErrTooLong) {
		t.Errorf("Encode(214 bytes) err = %v, want ErrTooLong", err)
	}
}

// The two copies of the format information must agree and decode to level M
// with a valid BCH remainder, otherwise scanners reject the symbol.
func TestFormatInfo(t *testing.T) {
	c, err := Encode([]byte("otpauth://totp/blip:someone@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=blip"))
	if err != nil {
		t.Fatal(err)
	}
	n := c.Size
	var a, b int
	for i := range 15 {
		var x, y int // first copy, around the top-left finder
		switch {
		case i < 6:
			x, y = 8, i
		case i < 8:
			x, y = 8, i+1
		case i == 8:
			x, y = 7, 8
		default:
			x, y = 14-i, 8
		}
		if c.Dark(x, y) {
			a |= 1 << i
		}
		if i < 8 { // second copy, split across the other two finders
			x, y = n-1-i, 8
		} else {
			x, y = 8, n-15+i
		}
		if c.Dark(x, y) {
			b |= 1 << i
		}
	}
	if a != b {
		t.Fatalf("format copies differ: %015b vs %015b", a, b)
	}
	f := a ^ 0x5412
	if level := f >> 13; level != 0 {
		t.Errorf("EC level bits = %02b, want 00 (M)", level)
	}
	rem := f
	for i := 14; i >= 10; i-- {
		if rem>>i&1 == 1 {
			rem ^= 0x537 << (i - 10)
		}
	}
	if rem != 0 {
		t.Errorf("format bits %015b fail the BCH check", a)
	}
}
