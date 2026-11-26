package qr

import (
	"bytes"
	"fmt"
	"testing"
)

// TestRoundTrip decodes encoded symbols the way a scanner does: read the
// format, unmask, collect codewords, de-interleave, check every block's
// Reed-Solomon syndromes (polynomial evaluation, independent of the
// encoder's division) and parse the byte-mode payload.
func TestRoundTrip(t *testing.T) {
	for _, n := range []int{1, 14, 15, 42, 43, 62, 84, 106, 122, 152, 180, 181, 213} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i*37 + n)
		}
		c, err := Encode(data)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decode(c)
		if err != nil {
			t.Errorf("%d bytes (size %d): %v", n, c.Size, err)
		} else if !bytes.Equal(got, data) {
			t.Errorf("%d bytes: decoded %x, want %x", n, got, data)
		}
	}
}

func decode(c *Code) ([]byte, error) {
	ver := (c.Size - 17) / 4
	// Format bits, first copy, then strip the XOR mask.
	pos := [15][2]int{{8, 0}, {8, 1}, {8, 2}, {8, 3}, {8, 4}, {8, 5}, {8, 7}, {8, 8}, {7, 8}, {5, 8}, {4, 8}, {3, 8}, {2, 8}, {1, 8}, {0, 8}}
	f := 0
	for i, p := range pos {
		if c.Dark(p[0], p[1]) {
			f |= 1 << i
		}
	}
	f ^= 0x5412
	if f>>13 != 0 {
		return nil, fmt.Errorf("EC level bits %02b, want M", f>>13)
	}
	mask := f >> 10 & 7

	masked := func(x, y int) bool {
		switch mask {
		case 0:
			return (x+y)%2 == 0
		case 1:
			return y%2 == 0
		case 2:
			return x%3 == 0
		case 3:
			return (x+y)%3 == 0
		case 4:
			return (x/3+y/2)%2 == 0
		case 5:
			return x*y%2+x*y%3 == 0
		case 6:
			return (x*y%2+x*y%3)%2 == 0
		}
		return ((x+y)%2+x*y%3)%2 == 0
	}

	// Function patterns are fixed per version.
	fn := newCode(ver).fn
	var bits []bool
	for right := c.Size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for v := range c.Size {
			y := v
			if (right+1)&2 == 0 {
				y = c.Size - 1 - v
			}
			for _, x := range []int{right, right - 1} {
				if !fn[y*c.Size+x] {
					bits = append(bits, c.Dark(x, y) != masked(x, y))
				}
			}
		}
	}
	words := make([]byte, len(bits)/8)
	for i := range words {
		for j := range 8 {
			if bits[i*8+j] {
				words[i] |= 1 << (7 - j)
			}
		}
	}

	// De-interleave: data codewords column by column, then EC the same way.
	l := layout[ver]
	blocks := make([][]byte, len(l.blocks))
	k := 0
	for i := range l.blocks[len(l.blocks)-1] {
		for b, n := range l.blocks {
			if i < n {
				blocks[b] = append(blocks[b], words[k])
				k++
			}
		}
	}
	for range l.ec {
		for b := range blocks {
			blocks[b] = append(blocks[b], words[k])
			k++
		}
	}
	var payload []byte
	for b, blk := range blocks {
		// A valid codeword has roots α^0..α^(ec-1).
		for i := range l.ec {
			root := byte(1)
			for range i {
				root = gfMul(root, 2)
			}
			var s byte
			for _, w := range blk {
				s = gfMul(s, root) ^ w
			}
			if s != 0 {
				return nil, fmt.Errorf("block %d: syndrome %d is %d", b, i, s)
			}
		}
		payload = append(payload, blk[:l.blocks[b]]...)
	}

	r := bitBuf{bytes: payload}
	read := func(n int) (v int) {
		for range n {
			v = v<<1 | int(r.bytes[r.n/8]>>(7-r.n%8)&1)
			r.n++
		}
		return v
	}
	if m := read(4); m != 0b0100 {
		return nil, fmt.Errorf("mode %04b, want byte mode", m)
	}
	count := 8
	if ver >= 10 {
		count = 16
	}
	out := make([]byte, read(count))
	for i := range out {
		out[i] = byte(read(8))
	}
	return out, nil
}
