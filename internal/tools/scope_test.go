package tools

import (
	"context"
	"encoding/json"
	"reflect"
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

func TestParseScopeServers(t *testing.T) {
	ints := []Integration{scoped{"alpha"}}
	s, err := ParseScope(ints, []byte(`{"metabase":{"database_id":[5,"7"],"query.database_id":5},"alpha":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	want := ServerRows{"database_id": {"5", "7"}, "query.database_id": {"5"}}
	if !reflect.DeepEqual(s["metabase"], want) || !reflect.DeepEqual(s["alpha"], []string{"x"}) {
		t.Fatalf("%+v", s)
	}
	for _, bad := range []string{`{"metabase":[5]}`, `{"metabase":{"database_id":[]}}`, `{"metabase":{"database_id":{"a":1}}}`, `{"metabase":{"database_id":[""]}}`, `{"metabase":{"":[1]}}`, `{"metabase":{}}`,
		// A built-in name whose integration is off is a mistake, never a server.
		`{"jenkins":{"job":["x"]}}`} {
		if _, err := ParseScope(ints, []byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestArgPaths(t *testing.T) {
	schema := map[string]any{"type": "object", "properties": map[string]any{
		"database_id": map[string]any{"type": "integer"},
		"query": map[string]any{"type": "object", "properties": map[string]any{
			"database_id": map[string]any{"type": "number"},
			"sql":         map[string]any{"type": "string"},
		}},
		"tags": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"mode": map[string]any{"type": "string", "enum": []any{"a", "b"}},
	}}
	got := ArgPaths(schema)
	want := []ArgPath{{Path: "database_id"}, {Path: "mode", Enum: []string{"a", "b"}}, {Path: "query.database_id"}, {Path: "query.sql"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	if ArgPaths(nil) != nil {
		t.Error("nil schema has paths")
	}
}

func TestCheckServer(t *testing.T) {
	s := Scope{"metabase": ServerRows{"database_id": {"5"}, "card_id": {"12", "40"}}}
	both := map[string]any{"type": "object", "properties": map[string]any{
		"database_id": map[string]any{"type": "integer"}, "card_id": map[string]any{"type": "integer"}}}
	none := map[string]any{"type": "object", "properties": map[string]any{"q": map[string]any{"type": "string"}}}
	cases := []struct {
		server string
		schema map[string]any
		args   string
		ok     bool
	}{
		{"metabase", both, `{"database_id":5}`, true},
		{"metabase", both, `{"database_id":"5"}`, true},
		{"metabase", both, `{"card_id":12}`, true},
		{"metabase", both, `{"database_id":9}`, false},
		{"metabase", both, `{"database_id":9,"card_id":12}`, false},
		{"metabase", both, `{}`, false},
		{"metabase", both, `{"database_id":null}`, false},
		{"metabase", none, `{}`, true},
		{"other", both, `{"database_id":9}`, true},
	}
	for _, c := range cases {
		_, err := s.CheckServer(c.server, c.schema, json.RawMessage(c.args))
		if (err == nil) != c.ok || (err != nil && !IsRefusal(err)) {
			t.Errorf("%s %s: %v", c.server, c.args, err)
		}
	}
	_, err := s.CheckServer("metabase", both, json.RawMessage(`{"database_id":9}`))
	if err == nil || !strings.HasPrefix(err.Error(), "refused: ") || !strings.Contains(err.Error(), "database_id") || !strings.Contains(err.Error(), "9") || !strings.Contains(err.Error(), "5") {
		t.Errorf("message: %v", err)
	}
	nested := Scope{"metabase": ServerRows{"query.database_id": {"5"}}}
	nschema := map[string]any{"type": "object", "properties": map[string]any{"query": map[string]any{"type": "object",
		"properties": map[string]any{"database_id": map[string]any{"type": "integer"}}}}}
	for args, ok := range map[string]bool{`{"query":{"database_id":5}}`: true, `{"query":{"database_id":9}}`: false, `{"query":"x"}`: false, `{}`: false} {
		if _, err := nested.CheckServer("metabase", nschema, json.RawMessage(args)); (err == nil) != ok {
			t.Errorf("nested %s: %v", args, err)
		}
	}
	// A server that shares a built-in key holds that family's scope, not rows, so it is not limited.
	if _, err := (Scope{"alpha": []string{"x"}}).CheckServer("alpha", both, json.RawMessage(`{"database_id":9}`)); err != nil {
		t.Errorf("built-in key read as rows: %v", err)
	}
}

func TestLosesLimit(t *testing.T) {
	s := Scope{"metabase": ServerRows{"database_id": {"5"}}}
	obj := func(names ...string) map[string]any {
		props := map[string]any{}
		for _, n := range names {
			props[n] = map[string]any{"type": "integer"}
		}
		return map[string]any{"type": "object", "properties": props}
	}
	if got := s.LosesLimit("metabase", obj("database_id"), obj("db_id")); !reflect.DeepEqual(got, []string{"database_id"}) {
		t.Errorf("renamed argument: %v", got)
	}
	if got := s.LosesLimit("metabase", obj("database_id"), obj("database_id", "x")); got != nil {
		t.Errorf("kept argument: %v", got)
	}
	if got := s.LosesLimit("metabase", obj("q"), obj("db_id")); got != nil {
		t.Errorf("was never limited: %v", got)
	}
	if got := s.LosesLimit("other", obj("database_id"), obj("db_id")); got != nil {
		t.Errorf("server without rows: %v", got)
	}
}

func TestCheckServerBypasses(t *testing.T) {
	obj := func(props map[string]any) map[string]any {
		return map[string]any{"type": "object", "properties": props}
	}
	integer := map[string]any{"type": "integer"}
	nested := Scope{"mb": ServerRows{"card_id": {"12"}, "query.database_id": {"5"}}}
	nschema := obj(map[string]any{"card_id": integer, "query": obj(map[string]any{"database_id": integer})})
	flat := Scope{"mb": ServerRows{"card_id": {"12", "40"}, "database_id": {"5"}}}
	cases := []struct {
		name   string
		s      Scope
		schema map[string]any
		args   string
		ok     bool
	}{
		{"parent is a JSON string", nested, nschema, `{"card_id":12,"query":"{\"database_id\":9}"}`, false},
		{"parent is an array", nested, nschema, `{"card_id":12,"query":[{"database_id":9}]}`, false},
		{"parent is null", nested, nschema, `{"card_id":12,"query":null}`, true},
		{"optional argument", flat, obj(map[string]any{"card_id": integer, "database_id": map[string]any{"anyOf": []any{integer, map[string]any{"type": "null"}}}}), `{"card_id":12,"database_id":9}`, false},
		{"undeclared row argument", flat, obj(map[string]any{"card_id": integer}), `{"card_id":12,"database_id":9}`, false},
		{"row argument sent to an unlimited tool", flat, obj(map[string]any{"q": map[string]any{"type": "string"}}), `{"database_id":9}`, false},
		{"unlimited tool without row arguments", flat, obj(map[string]any{"q": map[string]any{"type": "string"}}), `{"q":"x"}`, true},
		{"key differs only in case", flat, obj(map[string]any{"card_id": integer}), `{"card_id":12,"Card_ID":40}`, false},
		{"nested key differs only in case", nested, nschema, `{"card_id":12,"QUERY":{"database_id":9}}`, false},
		{"arguments are not an object", flat, obj(map[string]any{"card_id": integer}), `[]`, false},
	}
	for _, c := range cases {
		if _, err := c.s.CheckServer("mb", c.schema, json.RawMessage(c.args)); (err == nil) != c.ok {
			t.Errorf("%s: %s → %v", c.name, c.args, err)
		}
	}
	// The upstream gets what was checked: duplicate keys collapse to the value that passed.
	out, err := flat.CheckServer("mb", obj(map[string]any{"card_id": integer}), json.RawMessage(`{"card_id":12,"card_id":40}`))
	if err != nil || string(out) != `{"card_id":40}` {
		t.Errorf("forwarded %s, %v", out, err)
	}
}

func TestArgPathsUnionsAndRefs(t *testing.T) {
	schema := map[string]any{"type": "object",
		"$defs": map[string]any{"Q": map[string]any{"type": "object", "properties": map[string]any{"database_id": map[string]any{"type": "integer"}}}},
		"properties": map[string]any{
			"opt":   map[string]any{"anyOf": []any{map[string]any{"type": "integer"}, map[string]any{"type": "null"}}},
			"arr":   map[string]any{"type": []any{"string", "null"}},
			"bare":  map[string]any{"description": "no type"},
			"q":     map[string]any{"$ref": "#/$defs/Q"},
			"maybe": map[string]any{"anyOf": []any{map[string]any{"$ref": "#/$defs/Q"}, map[string]any{"type": "null"}}},
			"list":  map[string]any{"type": "array"},
		}}
	var got []string
	for _, a := range ArgPaths(schema) {
		got = append(got, a.Path)
	}
	if want := []string{"arr", "bare", "maybe.database_id", "opt", "q.database_id"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
