// Package ui holds the markup every valetkey page shares: the colour tokens for
// both themes, the fonts, the theme toggle script and the form submit feedback.
package ui

import (
	"embed"
	"html/template"
	"net/http"
)

//go:embed head.html
var head string

// Head opens <head> on every page: it carries the charset and applies the saved
// theme before first paint.
var Head = template.HTML(head)

//go:embed fonts/*.woff2
var fonts embed.FS

// Fonts serves the embedded fonts at /fonts/<file>.
func Fonts() http.Handler {
	files := http.FileServerFS(fonts)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=604800")
		files.ServeHTTP(w, r)
	})
}
