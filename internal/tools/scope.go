package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Restriction limits what a personal access token may do: which tools it sees
// and, through Scope, what those tools may reach.
type Restriction struct {
	TokenID string // the token's id, for the audit log
	Name    string // the token's name, for logs
	Tools   []string
	Scope   Scope

	MaxWritesPerHour int  // 0 means unlimited
	DryRun           bool // write tools report what they would do and never reach the upstream
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

// Scope is a token's parsed reach. A built-in integration's entry is keyed by
// its Scoper.ScopeKey, and an integration without one reaches nothing. Any
// other entry is keyed by the name of one of the user's own MCP servers and
// holds ServerRows.
type Scope map[string]any

// ServerRows limits the tools of one of the user's own MCP servers: argument
// path (dotted for nested ones) to the allowed values, as text.
type ServerRows map[string][]string

// ReservedKeys are the scope keys of the built-in integrations, on or off. No
// server of a user's own may take one of these names.
var ReservedKeys = []string{"argocd", "bitbucket", "jenkins", "loki", "metrics", "notion"}

// ParseScope reads a scope object against the enabled integrations. A key that
// is not an integration's names one of the user's servers and holds an object
// of argument path to a value or a list of values. Anything else, such as a
// typo of a built-in key or the key of an integration that is off, is refused
// so it cannot silently turn a limit into nothing. Whether a server key is
// really the user's is for the caller.
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
			rows, err := ParseServerRows(v)
			if slices.Contains(ReservedKeys, k) || errors.Is(err, errNotRows) {
				return nil, fmt.Errorf("scope: unknown key %q; this server knows %s", k, strings.Join(keys, ", "))
			}
			if err != nil {
				return nil, fmt.Errorf("scope: %s: %w", k, err)
			}
			s[k] = rows
			continue
		}
		parsed, err := sc.ParseScope(v)
		if err != nil {
			return nil, fmt.Errorf("scope: %s: %w", k, err)
		}
		s[k] = parsed
	}
	return s, nil
}

type scopeCtxKey struct{}

// ScopeOf returns the parsed scope a token gives the running tool's
// integration. ok is false when no token limits the call, as for a signed-in
// client. A Run that must ask its upstream whether something is in scope, such
// as a page under an allowed page, reads it here.
func ScopeOf(ctx context.Context) (scope any, ok bool) {
	v, ok := ctx.Value(scopeCtxKey{}).(scopeValue)
	return v.v, ok
}

type scopeValue struct{ v any }

// WithScope hands a tool's Run the parsed scope a token gives its integration.
func WithScope(ctx context.Context, scope any) context.Context {
	return context.WithValue(ctx, scopeCtxKey{}, scopeValue{scope})
}

// withScope carries the token's scope for in into a tool's Run.
func (s Scope) withScope(ctx context.Context, in Integration) context.Context {
	if sc, ok := in.(Scoper); ok {
		return WithScope(ctx, s[sc.ScopeKey()])
	}
	return ctx
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

var errNotRows = errors.New("expected an object of argument to allowed values")

// ParseServerRows reads one server's object of argument path to a value or a
// list of values.
func ParseServerRows(raw json.RawMessage) (ServerRows, error) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || len(obj) == 0 {
		return nil, errNotRows
	}
	rows := ServerRows{}
	for arg, v := range obj {
		if strings.TrimSpace(arg) == "" {
			return nil, errors.New("empty argument name")
		}
		var one any
		dec := json.NewDecoder(bytes.NewReader(v))
		dec.UseNumber()
		if err := dec.Decode(&one); err != nil {
			return nil, fmt.Errorf("%s: %w", arg, err)
		}
		list, isList := one.([]any)
		if !isList {
			list = []any{one}
		}
		if len(list) == 0 {
			return nil, fmt.Errorf("%s needs at least one value", arg)
		}
		for _, item := range list {
			text, ok := scalarText(item)
			if !ok || strings.TrimSpace(text) == "" {
				return nil, fmt.Errorf("%s values must be non-empty strings, numbers or booleans", arg)
			}
			rows[arg] = append(rows[arg], text)
		}
	}
	return rows, nil
}

// scalarText is a decoded JSON scalar as text, so 5 and "5" compare equal.
func scalarText(v any) (string, bool) {
	switch v := v.(type) {
	case string:
		return v, true
	case json.Number:
		return v.String(), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(v), true
	}
	return "", false
}

// ArgPath is a scalar argument of a tool, by its dotted path, with the values
// its schema allows when it lists them.
type ArgPath struct {
	Path string
	Enum []string
}

// ArgPaths lists a tool's scalar arguments by dotted path, descending into
// object properties. A property counts as scalar when its type, a type list,
// or a branch of its anyOf/oneOf is string, number, integer or boolean, or
// when it declares no type at all. Local $refs are followed. Arrays are
// skipped. Sorted by path.
func ArgPaths(schema map[string]any) []ArgPath {
	seen := map[string]int{}
	var out []ArgPath
	resolve := func(p map[string]any) map[string]any {
		ref, _ := p["$ref"].(string)
		for _, defs := range []string{"$defs", "definitions"} {
			if name, ok := strings.CutPrefix(ref, "#/"+defs+"/"); ok {
				table, _ := schema[defs].(map[string]any)
				if d, ok := table[name].(map[string]any); ok {
					return d
				}
			}
		}
		return p
	}
	var walk func(prefix string, node map[string]any, depth int)
	walk = func(prefix string, node map[string]any, depth int) {
		if depth > 8 { // ponytail: stops a recursive $ref; deeper arguments are not offered
			return
		}
		props, _ := node["properties"].(map[string]any)
		for name, p := range props {
			prop, _ := p.(map[string]any)
			path := prefix + name
			branches := []map[string]any{resolve(prop)}
			for _, key := range []string{"anyOf", "oneOf"} {
				list, _ := branches[0][key].([]any)
				for _, b := range list {
					if bm, ok := b.(map[string]any); ok {
						branches = append(branches, resolve(bm))
					}
				}
			}
			scalar := false
			var enum []string
			for i, b := range branches {
				var types []string
				switch t := b["type"].(type) {
				case string:
					types = []string{t}
				case []any:
					for _, x := range t {
						if xs, ok := x.(string); ok {
							types = append(types, xs)
						}
					}
				}
				_, hasProps := b["properties"]
				_, union := b["anyOf"]
				_, union2 := b["oneOf"]
				if slices.Contains(types, "object") || hasProps {
					walk(path+".", b, depth+1)
				}
				if i == 0 && len(types) == 0 && !hasProps && !union && !union2 {
					scalar = true
				}
				if slices.ContainsFunc(types, func(t string) bool { return slices.Contains([]string{"string", "number", "integer", "boolean"}, t) }) {
					scalar = true
				}
				if list, ok := b["enum"].([]any); ok {
					for _, e := range list {
						if text, ok := scalarText(e); ok {
							enum = append(enum, text)
						}
					}
				}
			}
			if scalar {
				if i, ok := seen[path]; ok {
					out[i].Enum = append(out[i].Enum, enum...)
					continue
				}
				seen[path] = len(out)
				out = append(out, ArgPath{Path: path, Enum: enum})
			}
		}
	}
	walk("", schema, 0)
	slices.SortFunc(out, func(a, b ArgPath) int { return strings.Compare(a.Path, b.Path) })
	return out
}

// Rows is the rows the scope holds for one of the user's servers. A built-in
// integration's entry is never rows, so a server that shares its key has none.
func (s Scope) Rows(server string) ServerRows {
	rows, _ := s[server].(ServerRows)
	return rows
}

// limitedBy is the server's row paths that schema has, sorted.
func (s Scope) limitedBy(server string, schema map[string]any) []string {
	rows := s.Rows(server)
	if len(rows) == 0 {
		return nil
	}
	var out []string
	for _, a := range ArgPaths(schema) {
		if _, ok := rows[a.Path]; ok {
			out = append(out, a.Path)
		}
	}
	return out
}

// CheckServer refuses a call to a tool of the user's server whose arguments
// reach beyond that server's rows, and returns the arguments to forward: the
// decoded call encoded again, so the upstream gets exactly what was checked.
//
// Every row path the call sends must hold an allowed value, whatever the
// tool's schema says. A tool whose schema has a row path must also be sent at
// least one; a tool whose schema has none is not limited beyond that. A key
// that differs from a row path segment only in case is refused, since some
// upstreams match keys without regard to case.
func (s Scope) CheckServer(server string, schema map[string]any, args json.RawMessage) (json.RawMessage, error) {
	rows := s.Rows(server)
	if len(rows) == 0 {
		return args, nil
	}
	var a any = map[string]any{}
	if len(bytes.TrimSpace(args)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(args))
		dec.UseNumber()
		if err := dec.Decode(&a); err != nil {
			return nil, Refuse("the arguments are not JSON: %v", err)
		}
	}
	paths := make([]string, 0, len(rows))
	for p := range rows {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	present := false
	for _, path := range paths {
		v, ok, err := lookup(a, path)
		if err != nil {
			return nil, Refuse("%s %s: %v", server, path, err)
		}
		if !ok {
			continue
		}
		present = true
		allowed := rows[path]
		if text, ok := scalarText(v); !ok || !slices.Contains(allowed, text) {
			return nil, Refuse("%s %s %s is outside this token's scope; it allows %s", server, path, compact(v), strings.Join(allowed, ", "))
		}
	}
	if limited := s.limitedBy(server, schema); !present && len(limited) > 0 {
		return nil, Refuse("this token limits %s by %s, and the call sends none of them", server, strings.Join(limited, " or "))
	}
	if len(bytes.TrimSpace(args)) == 0 {
		return args, nil
	}
	return json.Marshal(a)
}

// lookup walks a decoded call by a dotted path. A missing key or a null counts
// as absent. A segment whose parent is not an object, or a key that matches a
// segment only without regard to case, is an error: the upstream might read
// either one as the argument.
func lookup(v any, path string) (any, bool, error) {
	for _, seg := range strings.Split(path, ".") {
		if v == nil {
			return nil, false, nil
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, false, fmt.Errorf("%s sits under a value that is not an object", seg)
		}
		for k := range m {
			if k != seg && strings.EqualFold(k, seg) {
				return nil, false, fmt.Errorf("the call sends %q, which differs from %q only in case", k, seg)
			}
		}
		if v, ok = m[seg]; !ok {
			return nil, false, nil
		}
	}
	return v, v != nil, nil
}

func compact(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// LosesLimit is the row paths a tool of server was limited by before a schema
// change, when the new schema has none of them, so the tool would become
// unlimited for this scope. It is nil when nothing is lost.
func (s Scope) LosesLimit(server string, before, after map[string]any) []string {
	was := s.limitedBy(server, before)
	if len(was) == 0 || len(s.limitedBy(server, after)) > 0 {
		return nil
	}
	return was
}
