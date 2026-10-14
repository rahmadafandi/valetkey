package tools

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode"
)

// Restriction limits what a personal access token may do: which tools it sees
// and which jobs, repositories and log streams those tools may reach.
type Restriction struct {
	Name  string // the token's name, for logs
	Tools []string
	Scope Scope
}

// Allows reports whether the token may see and call tool at all.
func (r *Restriction) Allows(tool string) bool { return slices.Contains(r.Tools, tool) }

// Scope is a personal access token's reach, matching Halwa's repository
// "Tool reach" rules. A tool family without a key reaches nothing.
type Scope struct {
	Bitbucket string   `json:"bitbucket,omitempty"` // "workspace/slug"
	Jenkins   []string `json:"jenkins,omitempty"`   // job paths, e.g. "deploy-web" or "folder/job"
	Loki      string   `json:"loki,omitempty"`      // one LogQL stream selector
}

// ParseScope reads a scope object. jenkins may be a string or a list; unknown
// keys are refused so a typo cannot silently widen nothing into everything.
func ParseScope(raw []byte) (Scope, error) {
	var in struct {
		Bitbucket string          `json:"bitbucket"`
		Jenkins   json.RawMessage `json:"jenkins"`
		Loki      string          `json:"loki"`
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return Scope{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return Scope{}, fmt.Errorf("scope: %w", err)
	}
	s := Scope{Bitbucket: strings.TrimSpace(in.Bitbucket), Loki: strings.TrimSpace(in.Loki)}
	if len(in.Jenkins) > 0 && string(in.Jenkins) != "null" {
		var one string
		if json.Unmarshal(in.Jenkins, &one) == nil {
			s.Jenkins = []string{one}
		} else if err := json.Unmarshal(in.Jenkins, &s.Jenkins); err != nil {
			return Scope{}, errors.New("scope: jenkins must be a job name or a list of job names")
		}
	}
	for _, j := range s.Jenkins {
		if strings.TrimSpace(j) == "" {
			return Scope{}, errors.New("scope: empty jenkins job name")
		}
	}
	if s.Loki != "" {
		if sel, ok := streamSelectors(s.Loki); !ok || len(sel) != 1 {
			return Scope{}, errors.New("scope: loki must be one stream selector, e.g. {job=\"production/app\"}")
		}
	}
	return s, nil
}

var families = map[string]string{"jenkins_": "jenkins", "loki_": "loki", "bitbucket_": "bitbucket", "metrics_": "metrics", "argocd_": "argocd"}

// Check refuses a call whose arguments reach beyond the scope. Tools outside
// the scoped families (ops_status) pass.
func (s Scope) Check(tool string, args json.RawMessage) error {
	family := ""
	for prefix, name := range families {
		if strings.HasPrefix(tool, prefix) {
			family = name
		}
	}
	if family == "" {
		return nil
	}
	var a map[string]any
	json.Unmarshal(args, &a)
	text := func(k string) string { v, _ := a[k].(string); return v }
	switch family {
	case "jenkins":
		if len(s.Jenkins) == 0 {
			break
		}
		job, ok := jenkinsJob(text("jobURL"))
		if !ok {
			return fmt.Errorf("refused: %s: jobURL %q names no Jenkins job; this token allows %s", tool, text("jobURL"), strings.Join(s.Jenkins, ", "))
		}
		if !slices.Contains(s.Jenkins, job) {
			return fmt.Errorf("refused: %s: job %q is outside this token's scope; it allows %s", tool, job, strings.Join(s.Jenkins, ", "))
		}
		return nil
	case "loki":
		if s.Loki == "" {
			break
		}
		allowed := compact(s.Loki)
		selectors, ok := streamSelectors(text("query"))
		if !ok || len(selectors) == 0 {
			return fmt.Errorf("refused: %s: the query has no stream selector; this token allows %s", tool, s.Loki)
		}
		for _, sel := range selectors {
			if sel != allowed {
				return fmt.Errorf("refused: %s: stream selector %s is outside this token's scope; it allows %s", tool, sel, s.Loki)
			}
		}
		return nil
	case "bitbucket":
		if s.Bitbucket == "" {
			break
		}
		if text("repo") != s.Bitbucket {
			return fmt.Errorf("refused: %s: repository %q is outside this token's scope; it allows %s", tool, text("repo"), s.Bitbucket)
		}
		return nil
	}
	return fmt.Errorf("refused: %s: this token's scope names no %s, so it reaches none", tool, family)
}

// jenkinsJob is the job path in a Jenkins job URL: its /job/<name> parts.
func jenkinsJob(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	parts := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	var names []string
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] != "job" {
			continue
		}
		name, err := url.PathUnescape(parts[i+1])
		if err != nil || name == "" {
			return "", false
		}
		names = append(names, name)
		i++
	}
	return strings.Join(names, "/"), len(names) > 0
}

// streamSelectors is every {...} in a LogQL query, with the whitespace outside
// its quoted values removed. Braces inside quoted strings (a line filter's
// regex, a line_format template) are not selectors; an unclosed selector or
// string makes the query unreadable.
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

func compact(selector string) string {
	selectors, ok := streamSelectors(selector)
	if !ok || len(selectors) != 1 {
		return strings.TrimSpace(selector)
	}
	return selectors[0]
}
