// Package web embeds the UI: plain HTML, CSS and JavaScript with no build step.
package web

import "embed"

//go:embed *.html *.css *.js *.webmanifest *.svg *.png
var FS embed.FS

//go:generate go run genicons.go
