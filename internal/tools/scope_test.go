package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type scoped struct{ key string }

func (s scoped) System() string                        { return s.key }
func (s scoped) Title() string                         { return s.key }
func (s scoped) Fields() []Field                       { return nil }
func (s scoped) Validate(context.Context, Creds) error { return nil }
func (s scoped) Tools() []Tool                         { return []Tool{{Name: s.key + "_read"}} }
func (s scoped) ScopeKey() string                      { return s.key }
func (s scoped) ParseScope(raw json.RawMessage) (any, error) {
	return StringOrList(raw)
}
func (s scoped) CheckScope(v any, tool string, args json.RawMessage) error {
	var a struct{ Target string }
	json.Unmarshal(args, &a)
	for _, t := range v.([]string) {
		if t == a.Target {
			return nil
		}
	}
	return Refuse("%s: %s is outside this token's scope", tool, a.Target)
}

type unscoped struct{}

func (unscoped) System() string                        { return "plain" }
func (unscoped) Title() string                         { return "Plain" }
func (unscoped) Fields() []Field                       { return nil }
func (unscoped) Validate(context.Context, Creds) error { return nil }
func (unscoped) Tools() []Tool                         { return []Tool{{Name: "plain_read"}} }

func TestParseScope(t *testing.T) {
	ints := []Integration{scoped{"alpha"}, unscoped{}}
	if s, err := ParseScope(ints, []byte(`{"alpha":["x","y"]}`)); err != nil || len(s["alpha"].([]string)) != 2 {
		t.Fatalf("list: %v %v", s, err)
	}
	if s, err := ParseScope(ints, []byte(`{"alpha":"x"}`)); err != nil || s["alpha"].([]string)[0] != "x" {
		t.Fatalf("string: %v %v", s, err)
	}
	if s, err := ParseScope(ints, []byte(``)); err != nil || len(s) != 0 {
		t.Fatalf("empty: %v %v", s, err)
	}
	for _, bad := range []string{`{"alpa":"x"}`, `{"plain":"x"}`, `[]`, `{"alpha":3}`} {
		if _, err := ParseScope(ints, []byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestScopeCheck(t *testing.T) {
	a := scoped{"alpha"}
	s, _ := ParseScope([]Integration{a}, []byte(`{"alpha":"x"}`))
	if err := s.Check(a, "alpha_read", json.RawMessage(`{"target":"x"}`)); err != nil {
		t.Errorf("in scope: %v", err)
	}
	if err := s.Check(a, "alpha_read", json.RawMessage(`{"target":"y"}`)); !IsRefusal(err) {
		t.Errorf("out of scope: %v", err)
	}
	if err := (Scope{}).Check(a, "alpha_read", json.RawMessage(`{"target":"x"}`)); !IsRefusal(err) || !strings.Contains(err.Error(), "names no alpha") {
		t.Errorf("missing key: %v", err)
	}
	if err := s.Check(unscoped{}, "plain_read", nil); !IsRefusal(err) {
		t.Errorf("unscoped integration: %v", err)
	}
}
