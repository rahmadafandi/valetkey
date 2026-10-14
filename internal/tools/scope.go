package tools

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Restriction limits what a personal access token may do: which tools it sees
// and, through Scope, what those tools may reach.
type Restriction struct {
	Name  string // the token's name, for logs
	Tools []string
	Scope Scope
}

// Allows reports whether the token may see and call tool at all.
func (r *Restriction) Allows(tool string) bool { return slices.Contains(r.Tools, tool) }

// Scoper is implemented by integrations whose reach a personal access token
// can limit. ScopeKey names the token scope's JSON key.
type Scoper interface {
	ScopeKey() string
	ParseScope(raw json.RawMessage) (any, error)
	CheckScope(scope any, tool string, args json.RawMessage) error
}

// Scope is a token's parsed reach, keyed by Scoper.ScopeKey. An integration
// without a key reaches nothing.
type Scope map[string]any

// ParseScope reads a scope object against the enabled integrations. Unknown
// keys are refused so a typo cannot silently turn a limit into nothing.
func ParseScope(ints []Integration, raw []byte) (Scope, error) {
	s := Scope{}
	if len(bytes.TrimSpace(raw)) == 0 {
		return s, nil
	}
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("scope: expected a JSON object: %w", err)
	}
	scopers := map[string]Scoper{}
	var keys []string
	for _, i := range ints {
		if sc, ok := i.(Scoper); ok {
			scopers[sc.ScopeKey()] = sc
			keys = append(keys, sc.ScopeKey())
		}
	}
	for k, v := range in {
		sc, ok := scopers[k]
		if !ok {
			return nil, fmt.Errorf("scope: unknown key %q; this server knows %s", k, strings.Join(keys, ", "))
		}
		parsed, err := sc.ParseScope(v)
		if err != nil {
			return nil, fmt.Errorf("scope: %s: %w", k, err)
		}
		s[k] = parsed
	}
	return s, nil
}

// Check refuses a call whose arguments reach beyond the scope.
func (s Scope) Check(in Integration, tool string, args json.RawMessage) error {
	sc, ok := in.(Scoper)
	if !ok {
		return Refuse("%s: %s cannot be limited by a token, so tokens cannot use it", tool, in.Title())
	}
	v, ok := s[sc.ScopeKey()]
	if !ok {
		return Refuse("%s: this token's scope names no %s, so it reaches none", tool, sc.ScopeKey())
	}
	return sc.CheckScope(v, tool, args)
}

type refusal struct{ msg string }

func (r refusal) Error() string { return r.msg }

// Refuse builds an error that tells the agent what the fence allows; its text
// starts with "refused: ".
func Refuse(format string, a ...any) error { return refusal{"refused: " + fmt.Sprintf(format, a...)} }

// IsRefusal reports whether err, or an error it wraps, was built by Refuse.
func IsRefusal(err error) bool { return errors.As(err, new(refusal)) }

// StringOrList reads a JSON string or a list of non-empty strings.
func StringOrList(raw json.RawMessage) ([]string, error) {
	var list []string
	var one string
	if json.Unmarshal(raw, &one) == nil {
		list = []string{one}
	} else if err := json.Unmarshal(raw, &list); err != nil {
		return nil, errors.New("expected a string or a list of strings")
	}
	for i, v := range list {
		if list[i] = strings.TrimSpace(v); list[i] == "" {
			return nil, errors.New("empty entry")
		}
	}
	if len(list) == 0 {
		return nil, errors.New("empty list")
	}
	return list, nil
}
