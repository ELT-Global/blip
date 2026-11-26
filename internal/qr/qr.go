// Package qr encodes short byte strings (such as otpauth URIs) as QR codes:
// byte mode, error correction level M, versions 1–10 (up to 213 bytes).
// The layout follows ISO/IEC 18004 and Nayuki's reference implementation.
package qr

import (
	"errors"
	"strconv"
	"strings"
)

// Code is a square grid of modules; true is dark.
type Code struct {
	Size    int
	modules []bool
	fn      []bool // function patterns, excluded from data and masking
}

// Dark reports whether the module at column x, row y is dark.
func (c *Code) Dark(x, y int) bool { return c.modules[y*c.Size+x] }

// block layout per version for level M: EC codewords per block and the
// data-codeword lengths of each block.
var layout = [11]struct {
	ec     int
	blocks []int
}{
	1:  {10, []int{16}},
	2:  {16, []int{28}},
	3:  {26, []int{44}},
	4:  {18, []int{32, 32}},
	5:  {24, []int{43, 43}},
	6:  {16, []int{27, 27, 27, 27}},
	7:  {18, []int{31, 31, 31, 31}},
	8:  {22, []int{38, 38, 39, 39}},
	9:  {22, []int{36, 36, 36, 37, 37}},
	10: {26, []int{43, 43, 43, 43, 44}},
}

var alignment = [11][]int{2: {6, 18}, 3: {6, 22}, 4: {6, 26}, 5: {6, 30}, 6: {6, 34},
	7: {6, 22, 38}, 8: {6, 24, 42}, 9: {6, 26, 46}, 10: {6, 28, 50}}

// ErrTooLong is returned for data beyond version 10's capacity.
var ErrTooLong = errors.New("qr: data too long")

// Encode builds the smallest QR code that holds data.
func Encode(data []byte) (*Code, error) {
	ver, capacity := 0, 0
	for v := 1; v <= 10; v++ {
		capacity = sum(layout[v].blocks)
		countBits := 8
		if v >= 10 {
			countBits = 16
		}
		if 4+countBits+8*len(data) <= capacity*8 {
			ver = v
			break
		}
	}
	if ver == 0 {
		return nil, ErrTooLong
	}

	// Mode indicator, character count, payload, terminator, then pad bytes.
	var bb bitBuf
	bb.put(0b0100, 4)
	if ver >= 10 {
		bb.put(len(data), 16)
	} else {
		bb.put(len(data), 8)
	}
	for _, b := range data {
		bb.put(int(b), 8)
	}
	bb.put(0, min(4, capacity*8-bb.n))
	bb.put(0, (8-bb.n%8)%8)
	words := bb.bytes
	for pad := byte(0xEC); len(words) < capacity; pad ^= 0xEC ^ 0x11 {
		words = append(words, pad)
	}

	c := newCode(ver)
	c.place(interleave(words, ver))
	best, bestPenalty := 0, -1
	for mask := range 8 {
		c.applyMask(mask)
		c.drawFormat(mask)
		if p := c.penalty(); bestPenalty < 0 || p < bestPenalty {
			best, bestPenalty = mask, p
		}
		c.applyMask(mask) // XOR again to undo
	}
	c.applyMask(best)
	c.drawFormat(best)
	return c, nil
}

func sum(xs []int) (n int) {
	for _, x := range xs {
		n += x
	}
	return n
}

type bitBuf struct {
	bytes []byte
	n     int
}

func (b *bitBuf) put(v, bits int) {
	for i := bits - 1; i >= 0; i-- {
		if b.n%8 == 0 {
			b.bytes = append(b.bytes, 0)
		}
		b.bytes[b.n/8] |= byte((v>>i)&1) << (7 - b.n%8)
		b.n++
	}
}

// interleave splits data into blocks, appends Reed-Solomon EC to each and
// interleaves them column-wise as the standard requires.
func interleave(data []byte, ver int) []byte {
	l := layout[ver]
	div := rsDivisor(l.ec)
	var blocks, ecs [][]byte
	for _, n := range l.blocks {
		blocks = append(blocks, data[:n])
		ecs = append(ecs, rsRemainder(data[:n], div))
		data = data[n:]
	}
	var out []byte
	for i := range l.blocks[len(l.blocks)-1] {
		for _, b := range blocks {
			if i < len(b) {
				out = append(out, b[i])
			}
		}
	}
	for i := range l.ec {
		for _, e := range ecs {
			out = append(out, e[i])
		}
	}
	return out
}

func gfMul(x, y byte) byte {
	var z byte
	for i := 7; i >= 0; i-- {
		z = z<<1 ^ (z>>7)*0x1D
		z ^= (y >> i & 1) * x
	}
	return z
}

func rsDivisor(degree int) []byte {
	r := make([]byte, degree)
	r[degree-1] = 1
	root := byte(1)
	for range degree {
		for j := range r {
			r[j] = gfMul(r[j], root)
			if j+1 < len(r) {
				r[j] ^= r[j+1]
			}
		}
		root = gfMul(root, 2)
	}
	return r
}

func rsRemainder(data, div []byte) []byte {
	r := make([]byte, len(div))
	for _, b := range data {
		f := b ^ r[0]
		copy(r, r[1:])
		r[len(r)-1] = 0
		for i, d := range div {
			r[i] ^= gfMul(d, f)
		}
	}
	return r
}

func newCode(ver int) *Code {
	size := ver*4 + 17
	c := &Code{Size: size, modules: make([]bool, size*size), fn: make([]bool, size*size)}
	for i := range size {
		c.setFn(6, i, i%2 == 0)
		c.setFn(i, 6, i%2 == 0)
	}
	c.finder(3, 3)
	c.finder(size-4, 3)
	c.finder(3, size-4)
	pos := alignment[ver]
	for i, x := range pos {
		for j, y := range pos {
			last := len(pos) - 1
			if (i == 0 && j == 0) || (i == 0 && j == last) || (i == last && j == 0) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					c.setFn(x+dx, y+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	c.drawFormat(0) // reserve format areas before data placement
	if ver >= 7 {
		rem := ver
		for range 12 {
			rem = rem<<1 ^ (rem>>11)*0x1F25
		}
		bits := ver<<12 | rem
		for i := range 18 {
			dark := bits>>i&1 == 1
			a, b := size-11+i%3, i/3
			c.setFn(a, b, dark)
			c.setFn(b, a, dark)
		}
	}
	return c
}

func (c *Code) setFn(x, y int, dark bool) {
	c.modules[y*c.Size+x] = dark
	c.fn[y*c.Size+x] = true
}

func (c *Code) finder(cx, cy int) {
	for dy := -4; dy <= 4; dy++ {
		for dx := -4; dx <= 4; dx++ {
			x, y := cx+dx, cy+dy
			if x >= 0 && x < c.Size && y >= 0 && y < c.Size {
				d := max(abs(dx), abs(dy))
				c.setFn(x, y, d != 2 && d != 4)
			}
		}
	}
}

func (c *Code) drawFormat(mask int) {
	data := mask // level M's format bits are 00
	rem := data
	for range 10 {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	bits := (data<<10 | rem) ^ 0x5412
	bit := func(i int) bool { return bits>>i&1 == 1 }
	n := c.Size
	for i := range 6 {
		c.setFn(8, i, bit(i))
	}
	c.setFn(8, 7, bit(6))
	c.setFn(8, 8, bit(7))
	c.setFn(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		c.setFn(14-i, 8, bit(i))
	}
	for i := range 8 {
		c.setFn(n-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		c.setFn(8, n-15+i, bit(i))
	}
	c.setFn(8, n-8, true) // always-dark module
}

// place writes codewords in the standard zigzag, two columns at a time from
// the bottom right, skipping the vertical timing column.
func (c *Code) place(words []byte) {
	n, i := c.Size, 0
	for right := n - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		up := (right+1)&2 == 0
		for v := range n {
			y := v
			if up {
				y = n - 1 - v
			}
			for j := range 2 {
				x := right - j
				if k := y*n + x; !c.fn[k] && i < len(words)*8 {
					c.modules[k] = words[i>>3]>>(7-i&7)&1 == 1
					i++
				}
			}
		}
	}
}

func (c *Code) applyMask(mask int) {
	for y := range c.Size {
		for x := range c.Size {
			var inv bool
			switch mask {
			case 0:
				inv = (x+y)%2 == 0
			case 1:
				inv = y%2 == 0
			case 2:
				inv = x%3 == 0
			case 3:
				inv = (x+y)%3 == 0
			case 4:
				inv = (x/3+y/2)%2 == 0
			case 5:
				inv = x*y%2+x*y%3 == 0
			case 6:
				inv = (x*y%2+x*y%3)%2 == 0
			case 7:
				inv = ((x+y)%2+x*y%3)%2 == 0
			}
			if k := y*c.Size + x; inv && !c.fn[k] {
				c.modules[k] = !c.modules[k]
			}
		}
	}
}

// penalty scores a masked symbol by the four ISO rules; lower is better.
func (c *Code) penalty() int {
	n, p, dark := c.Size, 0, 0
	line := func(get func(i int) bool) {
		run, hist := 0, uint16(0)
		var prev bool
		for i := range n {
			d := get(i)
			if i > 0 && d == prev {
				run++
				if run == 5 {
					p += 3
				} else if run > 5 {
					p++
				}
			} else {
				run = 1
			}
			prev = d
			// finder-like 1:1:3:1:1 with four light modules on either side
			hist = hist<<1 | b2u(d)
			if i >= 10 && (hist&0x7FF == 0x5D0 || hist&0x7FF == 0x05D) {
				p += 40
			}
		}
	}
	for y := range n {
		line(func(x int) bool { return c.Dark(x, y) })
	}
	for x := range n {
		line(func(y int) bool { return c.Dark(x, y) })
	}
	for y := range n {
		for x := range n {
			d := c.Dark(x, y)
			if d {
				dark++
			}
			if x < n-1 && y < n-1 && d == c.Dark(x+1, y) && d == c.Dark(x, y+1) && d == c.Dark(x+1, y+1) {
				p += 3
			}
		}
	}
	total := n * n
	k := (abs(dark*20-total*10) + total - 1) / total
	return p + (k-1)*10
}

func b2u(b bool) uint16 {
	if b {
		return 1
	}
	return 0
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// SVG renders the code with a 4-module quiet zone as a single path.
func (c *Code) SVG() string {
	var b strings.Builder
	s := strconv.Itoa(c.Size + 8)
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ` + s + " " + s + `" shape-rendering="crispEdges">`)
	b.WriteString(`<rect width="100%" height="100%" fill="#fff"/><path fill="#000" d="`)
	for y := range c.Size {
		for x := range c.Size {
			if c.Dark(x, y) {
				b.WriteString("M" + strconv.Itoa(x+4) + " " + strconv.Itoa(y+4) + "h1v1h-1z")
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String()
}

// Terminal renders the code with half-block characters, two rows per line,
// light-on-dark so it scans from a typical terminal.
func (c *Code) Terminal() string {
	var b strings.Builder
	q := 2 // quiet zone
	light := func(x, y int) bool {
		x, y = x-q, y-q
		return x < 0 || y < 0 || x >= c.Size || y >= c.Size || !c.Dark(x, y)
	}
	for y := 0; y < c.Size+2*q; y += 2 {
		for x := range c.Size + 2*q {
			top, bot := light(x, y), light(x, y+1)
			switch {
			case top && bot:
				b.WriteRune('█')
			case top:
				b.WriteRune('▀')
			case bot:
				b.WriteRune('▄')
			default:
				b.WriteByte(' ')
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}
