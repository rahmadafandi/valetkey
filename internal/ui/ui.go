// Package ui holds the markup every valetkey page shares: the colour tokens for
// both themes, the theme toggle script and the form submit feedback.
package ui

import (
	_ "embed"
	"html/template"
)

//go:embed head.html
var head string

// Head opens <head> on every page: it carries the charset and applies the saved
// theme before first paint.
var Head = template.HTML(head)
