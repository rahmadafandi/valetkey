package web

import (
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"

	"github.com/rahmadafandi/valetkey/internal/tools"
)

// The token forms carry a scope as plain fields, never as JSON:
//
//	scope.<key>                  a built-in integration's values, one per line
//	arg.<server>, vals.<server>  repeated pairs, in order: an argument of one of
//	                             the user's servers and its values, one per line
//
// A pair with neither an argument nor values is a spare row and is dropped.

// familyText is how the form words one built-in integration's scope.
type familyText struct {
	Label, Note, Placeholder string
	Single                   bool // the scope is one value, not a list
}

var familyTexts = map[string]familyText{
	"bitbucket": {Label: "Bitbucket repositories", Note: "Each one as workspace/repo.", Placeholder: "acme/web"},
	"jenkins":   {Label: "Jenkins jobs", Note: "Job paths, such as deploy-web or folder/deploy-web.", Placeholder: "deploy-web"},
	"loki":      {Label: "Loki stream selectors", Note: "A query may only use the selectors listed here.", Placeholder: `{app="web"}`},
	"metrics":   {Label: "Metrics selector", Note: "One selector. Every query must carry its labels.", Placeholder: `{namespace="web"}`, Single: true},
	"argocd":    {Label: "Argo CD apps", Note: "App names.", Placeholder: "web"},
	"notion":    {Label: "Notion pages", Note: "Page or database IDs or links. The token reaches those and everything under them."},
}

// familyField is one built-in integration's scope on the form.
type familyField struct {
	familyText
	Key, Value string
}

// scopeRow is one argument of a server's scope and its values, one per line.
type scopeRow struct {
	Arg, Values string
	Enum        []string // the argument's allowed values, when its schema lists them
	Stale       bool     // no approved tool of the server has this argument
}

// scopeInput is a scope as the form shows it: what was saved, or what was just submitted.
type scopeInput struct {
	Families map[string]string     // scope key → values, one per line
	Rows     map[string][]scopeRow // server → rows
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func inputFromForm(f url.Values) scopeInput {
	in := scopeInput{Families: map[string]string{}, Rows: map[string][]scopeRow{}}
	for key, vals := range f {
		if fam, ok := strings.CutPrefix(key, "scope."); ok && len(vals) > 0 {
			in.Families[fam] = vals[0]
		}
		server, ok := strings.CutPrefix(key, "arg.")
		if !ok {
			continue
		}
		values := f["vals."+server]
		for i, arg := range vals {
			row := scopeRow{Arg: strings.TrimSpace(arg)}
			if i < len(values) {
				row.Values = values[i]
			}
			in.Rows[server] = append(in.Rows[server], row)
		}
	}
	return in
}

// inputFromStored reads a stored scope back into form fields. A scope that
// does not read as one shows as empty.
func inputFromStored(raw []byte) scopeInput {
	in := scopeInput{Families: map[string]string{}, Rows: map[string][]scopeRow{}}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return in
	}
	for key, v := range obj {
		if list, err := tools.StringOrList(v); err == nil {
			in.Families[key] = strings.Join(list, "\n")
			continue
		}
		rows, err := tools.ParseServerRows(v)
		if err != nil {
			continue
		}
		for arg, vals := range rows {
			in.Rows[key] = append(in.Rows[key], scopeRow{Arg: arg, Values: strings.Join(vals, "\n")})
		}
		slices.SortFunc(in.Rows[key], func(a, b scopeRow) int { return strings.Compare(a.Arg, b.Arg) })
	}
	return in
}

// stored is the scope as JSON for tools.ParseScope, which decides whether its
// values are good. It only refuses a server row that is half filled in.
func (in scopeInput) stored() ([]byte, error) {
	raw := map[string]any{}
	for fam, text := range in.Families {
		switch vals := lines(text); len(vals) {
		case 0:
		case 1:
			raw[fam] = vals[0]
		default:
			raw[fam] = vals
		}
	}
	for server, rows := range in.Rows {
		args := map[string][]string{}
		for _, r := range rows {
			vals := lines(r.Values)
			switch {
			case r.Arg == "" && len(vals) == 0: // the spare row
			case r.Arg == "":
				return nil, errors.New("Pick an argument for the values " + strings.Join(vals, ", ") + " under " + server + ".")
			case len(vals) == 0:
				// Dropping it would leave the token unlimited without a word.
				return nil, errors.New("Add at least one value for " + r.Arg + " under " + server + ", or clear the row.")
			default:
				args[r.Arg] = append(args[r.Arg], vals...)
			}
		}
		if len(args) > 0 {
			raw[server] = args
		}
	}
	return json.Marshal(raw)
}

// ownServers refuses rows under a server that is not one of the user's, or
// that has a built-in name and so cannot be limited.
func (in scopeInput) ownServers(servers []tools.Integration) error {
	for name, rows := range in.Rows {
		if !slices.ContainsFunc(rows, func(r scopeRow) bool { return r.Arg != "" || len(lines(r.Values)) > 0 }) {
			continue
		}
		ok := !slices.Contains(tools.ReservedKeys, name) && slices.ContainsFunc(servers, func(s tools.Integration) bool { return s.Title() == name })
		if !ok {
			return errors.New("Unknown server " + name + ".")
		}
	}
	return nil
}

// serverForm is one of the user's servers on the token form.
type serverForm struct {
	Name     string
	Reserved bool // shares a name with a built-in scope key, so it cannot be limited
	Args     []tools.ArgPath
	Rows     []scopeRow // saved or submitted rows, then one spare
	Tools    []toolRow
}

// scopeView is what the token form shows.
type scopeView struct {
	Families []familyField
	Servers  []serverForm
}

// view lays the input out over the built-in integrations that can be limited
// and over the user's servers with their approved tools.
func (in scopeInput) view(ints, servers []tools.Integration, checked []string) scopeView {
	var v scopeView
	for _, i := range ints {
		sc, ok := i.(tools.Scoper)
		if !ok {
			continue
		}
		text, ok := familyTexts[sc.ScopeKey()]
		if !ok {
			text = familyText{Label: i.Title()}
		}
		v.Families = append(v.Families, familyField{familyText: text, Key: sc.ScopeKey(), Value: in.Families[sc.ScopeKey()]})
	}
	for _, srv := range servers {
		sf := serverForm{Name: srv.Title(), Reserved: slices.Contains(tools.ReservedKeys, srv.Title())}
		known := map[string][]string{}
		for _, t := range srv.Tools() {
			for _, a := range tools.ArgPaths(t.Schema) {
				if _, ok := known[a.Path]; !ok {
					known[a.Path] = a.Enum
					sf.Args = append(sf.Args, a)
				}
			}
		}
		slices.SortFunc(sf.Args, func(a, b tools.ArgPath) int { return strings.Compare(a.Path, b.Path) })
		var limits []string
		for _, r := range in.Rows[sf.Name] {
			if r.Arg == "" && strings.TrimSpace(r.Values) == "" {
				continue
			}
			enum, ok := known[r.Arg]
			r.Enum, r.Stale = enum, r.Arg != "" && !ok
			sf.Rows = append(sf.Rows, r)
			if r.Arg != "" && len(lines(r.Values)) > 0 {
				limits = append(limits, r.Arg)
			}
		}
		if !sf.Reserved {
			sf.Rows = append(sf.Rows, scopeRow{})
		}
		for _, t := range srv.Tools() {
			row := toolRow{Name: t.Name, Description: t.Description, Destructive: t.Destructive, Checked: slices.Contains(checked, t.Name)}
			for _, a := range tools.ArgPaths(t.Schema) {
				row.Args = append(row.Args, a.Path)
			}
			if len(limits) > 0 && !sf.Reserved {
				var by []string
				for _, a := range row.Args {
					if slices.Contains(limits, a) && !slices.Contains(by, a) {
						by = append(by, a)
					}
				}
				row.Limit = "not limited by scope"
				if len(by) > 0 {
					row.Limit = "limited: " + strings.Join(by, ", ")
				}
			}
			sf.Tools = append(sf.Tools, row)
		}
		v.Servers = append(v.Servers, sf)
	}
	return v
}
