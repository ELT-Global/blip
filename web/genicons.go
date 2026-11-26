//go:build ignore

// genicons rasterises the icon.svg glyph into the PNG sizes the web app
// manifest needs. Run with: go generate ./web
package main

import (
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"strconv"
)

var (
	bg    = color.RGBA{0x0b, 0x14, 0x26, 0xff}
	azure = color.RGBA{0x2b, 0x8c, 0xff, 0xff}
	light = color.RGBA{0x63, 0xaa, 0xff, 0xff}
	line  = [][2]float64{{9, 34}, {20, 34}, {25, 22}, {33, 44}, {39, 30}, {42, 34}, {47, 34}}
)

const scale = 0.8 // keep the glyph inside the maskable safe zone

func main() {
	for _, size := range []int{192, 512} {
		img := image.NewRGBA(image.Rect(0, 0, size, size))
		const ss = 4 // supersampling per axis
		for py := range size {
			for px := range size {
				var r, g, b float64
				for sy := range ss {
					for sx := range ss {
						// map to the 64-unit SVG space, scaled about the centre
						x := ((float64(px)+(float64(sx)+.5)/ss)/float64(size)*64-32)/scale + 32
						y := ((float64(py)+(float64(sy)+.5)/ss)/float64(size)*64-32)/scale + 32
						c := sample(x, y)
						r, g, b = r+float64(c.R), g+float64(c.G), b+float64(c.B)
					}
				}
				n := float64(ss * ss)
				img.Set(px, py, color.RGBA{uint8(r / n), uint8(g / n), uint8(b / n), 0xff})
			}
		}
		f, err := os.Create("icon-" + strconv.Itoa(size) + ".png")
		if err != nil {
			panic(err)
		}
		if err := png.Encode(f, img); err != nil {
			panic(err)
		}
		f.Close()
	}
}

func sample(x, y float64) color.RGBA {
	if math.Hypot(x-52, y-34) <= 4.5 {
		return light
	}
	for i := 1; i < len(line); i++ {
		if segDist(x, y, line[i-1], line[i]) <= 2.5 {
			return azure
		}
	}
	return bg
}

func segDist(x, y float64, a, b [2]float64) float64 {
	dx, dy := b[0]-a[0], b[1]-a[1]
	t := math.Max(0, math.Min(1, ((x-a[0])*dx+(y-a[1])*dy)/(dx*dx+dy*dy)))
	return math.Hypot(x-a[0]-t*dx, y-a[1]-t*dy)
}
