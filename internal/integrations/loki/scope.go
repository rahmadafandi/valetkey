package loki

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode"

	"github.com/rahmadafandi/valetkey/internal/tools"
)

func (l *Loki) ScopeKey() string { return "loki" }

// ParseScope reads one LogQL stream selector, e.g. {app="web"}.
func (l *Loki) ParseScope(raw json.RawMessage) (any, error) {
	var sel string
	if err := json.Unmarshal(raw, &sel); err != nil {
		return nil, errors.New(`expected one stream selector string such as {app="web"}`)
	}
	sel = strings.TrimSpace(sel)
	selectors, ok := streamSelectors(sel)
	if !ok || len(selectors) != 1 || !strings.HasPrefix(sel, "{") || !strings.HasSuffix(sel, "}") {
		return nil, errors.New(`expected one stream selector such as {app="web"}`)
	}
	return selectors[0], nil
}

// CheckScope requires every stream selector in the query to equal the scoped one.
func (l *Loki) CheckScope(scope any, tool string, args json.RawMessage) error {
	allowed := scope.(string)
	var a struct {
		Query string `json:"query"`
	}
	json.Unmarshal(args, &a)
	selectors, ok := streamSelectors(a.Query)
	if !ok || len(selectors) == 0 {
		return tools.Refuse("%s: the query has no stream selector; this token allows %s", tool, allowed)
	}
	for _, sel := range selectors {
		if sel != allowed {
			return tools.Refuse("%s: stream selector %s is outside this token's scope; it allows %s", tool, sel, allowed)
		}
	}
	return nil
}

// streamSelectors is every {...} in a LogQL query, with the whitespace outside
// its quoted values removed. Braces inside quoted strings (a line filter's
// regex, a line_format template) are not selectors; an unclosed selector or
// string makes the query unreadable, and so does a # comment, which could hide
// a quote from this scanner but not from Loki.
func streamSelectors(query string) ([]string, bool) {
	var selectors []string
	var current *strings.Builder
	quote := rune(0)
	escaped := false
	for _, r := range query {
		if quote != 0 {
			if current != nil {
				current.WriteRune(r)
			}
			switch {
			case escaped:
				escaped = false
			case r == '\\' && quote == '"':
				escaped = true
			case r == quote:
				quote = 0
			}
			continue
		}
		switch {
		case r == '#':
			return nil, false
		case r == '"' || r == '`':
			quote = r
		case r == '{' && current == nil:
			current = &strings.Builder{}
		case r == '{':
			return nil, false
		case r == '}' && current != nil:
			current.WriteRune(r)
			selectors = append(selectors, current.String())
			current = nil
			continue
		}
		if current != nil && !unicode.IsSpace(r) {
			current.WriteRune(r)
		}
	}
	return selectors, quote == 0 && current == nil
}
