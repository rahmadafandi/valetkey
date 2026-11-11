// Package proxy is valetkey's MCP client for the remote MCP servers users
// register: it fetches their tools for review, compares them with the approved
// snapshot, and serves the approved snapshot as valetkey tools.
package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rahmadafandi/valetkey/internal/creds"
	"github.com/rahmadafandi/valetkey/internal/netguard"
	"github.com/rahmadafandi/valetkey/internal/store"
	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/upstream"
)

type Proxy struct {
	Store     *store.Store
	Creds     creds.Store
	Guard     *netguard.Guard
	PublicURL string
	Log       *slog.Logger
}

func (p *Proxy) log() *slog.Logger {
	if p.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return p.Log
}

// CredsSystem is the credentials row holding an upstream's login.
func CredsSystem(upstreamID string) string { return "upstream:" + upstreamID }

// Digest identifies a fetched tool set, so approval can insist on exactly the set the user saw.
func Digest(cs []Candidate) string {
	out := sorted(cs)
	for i := range out {
		if s, err := canonical(out[i].Schema); err == nil {
			out[i].Schema = s
		}
	}
	b, _ := json.Marshal(out)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type Diff struct {
	Added, Removed []string
	Changed        []Change
}

// Change names a tool present in both sets and which parts of it differ.
type Change struct {
	Name                        string
	Description, Schema, Writes bool
}

// Compare reports how a fresh fetch differs from the approved snapshot, by upstream tool name.
func Compare(approved []store.UpstreamTool, fetched []Candidate) Diff {
	var d Diff
	old := make(map[string]store.UpstreamTool, len(approved))
	for _, t := range approved {
		old[t.Name] = t
	}
	now := map[string]bool{}
	for _, c := range sorted(fetched) {
		now[c.Name] = true
		a, ok := old[c.Name]
		if !ok {
			d.Added = append(d.Added, c.Name)
			continue
		}
		ch := Change{Name: c.Name, Description: a.Description != c.Description, Schema: !sameSchema(a.InputSchema, c.Schema), Writes: a.Writes != c.Writes}
		if ch.Description || ch.Schema || ch.Writes {
			d.Changed = append(d.Changed, ch)
		}
	}
	for _, t := range approved {
		if !now[t.Name] {
			d.Removed = append(d.Removed, t.Name)
		}
	}
	return d
}

// Snapshot turns the candidates the user approved into rows for store.ApproveTools.
func Snapshot(cs []Candidate) []store.UpstreamTool {
	out := make([]store.UpstreamTool, len(cs))
	for i, c := range cs {
		out[i] = store.UpstreamTool{Name: c.Name, Description: c.Description, InputSchema: string(c.Schema), Writes: c.Writes}
	}
	return out
}

// Integrations serves each of the user's upstreams that has approved tools.
// It reads only the stored snapshot, never the upstream's live list.
func (p *Proxy) Integrations(ctx context.Context, userID string) ([]tools.Integration, error) {
	rows, err := p.Store.UserTools(ctx, userID)
	if err != nil {
		return nil, err
	}
	var out []tools.Integration
	var cur *integration
	for _, r := range rows {
		if cur == nil || cur.u.ID != r.Upstream.ID {
			out = append(out, &integration{p: p, userID: userID, u: r.Upstream})
			cur = out[len(out)-1].(*integration)
		}
		cur.tools = append(cur.tools, r.Tool)
	}
	return out, nil
}

type integration struct {
	p      *Proxy
	userID string // whose credentials a refreshed OAuth login is saved for
	u      store.Upstream
	tools  []store.UpstreamTool
}

func (i *integration) System() string { return CredsSystem(i.u.ID) }
func (i *integration) Title() string  { return i.u.Name }

func (i *integration) Fields() []tools.Field {
	if i.u.Auth == "none" {
		return nil
	}
	// Only its presence matters: the handler loads credentials when Fields is not empty.
	return []tools.Field{{Name: "credential", Secret: true}}
}

func (i *integration) Validate(context.Context, tools.Creds) error { return nil }
func (i *integration) ConnectURL(publicURL string) string          { return publicURL + "/upstreams" }

func (i *integration) Tools() []tools.Tool {
	var out []tools.Tool
	for _, row := range i.tools {
		name, ok := ToolName(i.u.Name, row.Name)
		var schema map[string]any
		if _, err := canonical(json.RawMessage(row.InputSchema)); !ok || err != nil || json.Unmarshal([]byte(row.InputSchema), &schema) != nil {
			i.p.log().Warn("skipping unusable approved tool", "upstream", i.u.ID, "tool", row.Name)
			continue
		}
		schema, nullable := optionalNulls(schema)
		out = append(out, tools.Tool{
			Name: name, Description: row.Description, Schema: schema,
			Destructive: row.Writes, Unscoped: true,
			Run: i.caller(row.Name, nullable),
		})
	}
	return out
}

// caller opens a session per call: initialize, tools/call with the upstream's own name, close.
// An OAuth login is refreshed when it is about to expire, or once after a 401.
// ponytail: two round trips per call; pool sessions per (user, upstream) if latency matters.
func (i *integration) caller(tool string, nullable []string) func(ctx context.Context, c tools.Creds, args json.RawMessage) (string, error) {
	return func(ctx context.Context, c tools.Creds, args json.RawMessage) (string, error) {
		if len(args) == 0 || string(args) == "null" {
			args = json.RawMessage("{}")
		}
		args = fillNulls(args, nullable)
		oauth := i.u.Auth == "oauth" && c["pending"] == ""
		refreshed := false
		if oauth && expiring(c) {
			var err error
			if c, err = i.p.refresh(ctx, i.userID, i.u, c["access_token"]); err != nil {
				return "", i.safe(tool, err)
			}
			refreshed = true
		}
		out, err := i.call(ctx, tool, c, args)
		// A 401 comes before the upstream runs the tool, so retrying cannot repeat a write.
		if oauth && !refreshed && errors.Is(err, upstream.ErrUnauthorized) {
			if c, err = i.p.refresh(ctx, i.userID, i.u, c["access_token"]); err != nil {
				return "", i.safe(tool, err)
			}
			out, err = i.call(ctx, tool, c, args)
		}
		return out, i.safe(tool, err)
	}
}

// optionalNulls drops from a schema's required list the properties that accept
// null, and returns their names. Some servers require every argument but
// refuse a value for one that does not apply (Metabase: "include_hidden does
// not apply to action list_databases"); an agent made to fill each one sends
// a default and is refused. Optional, it leaves them out, and fillNulls sends
// null, which such a server reads as absent.
func optionalNulls(schema map[string]any) (map[string]any, []string) {
	req, _ := schema["required"].([]any)
	props, _ := schema["properties"].(map[string]any)
	var keep []any
	var nullable []string
	for _, r := range req {
		name, _ := r.(string)
		if p, ok := props[name].(map[string]any); ok && acceptsNull(p) {
			nullable = append(nullable, name)
			continue
		}
		keep = append(keep, r)
	}
	if len(nullable) == 0 {
		return schema, nil
	}
	if len(keep) == 0 {
		delete(schema, "required")
	} else {
		schema["required"] = keep
	}
	return schema, nullable
}

// acceptsNull reports whether a property schema allows null: type "null", a
// type list holding it, or a oneOf/anyOf branch that does.
func acceptsNull(p map[string]any) bool {
	switch t := p["type"].(type) {
	case string:
		if t == "null" {
			return true
		}
	case []any:
		if slices.Contains(t, any("null")) {
			return true
		}
	}
	for _, k := range []string{"oneOf", "anyOf"} {
		branches, _ := p[k].([]any)
		for _, b := range branches {
			if m, ok := b.(map[string]any); ok && acceptsNull(m) {
				return true
			}
		}
	}
	return false
}

// fillNulls sets each of names the call leaves out to null, as the upstream
// still requires them. Arguments that are not an object pass through.
func fillNulls(args json.RawMessage, names []string) json.RawMessage {
	if len(names) == 0 {
		return args
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(args, &m) != nil || m == nil {
		return args
	}
	added := false
	for _, n := range names {
		if _, ok := m[n]; !ok {
			m[n], added = json.RawMessage("null"), true
		}
	}
	if !added {
		return args
	}
	out, err := json.Marshal(m)
	if err != nil {
		return args
	}
	return out
}

// toolError is the upstream's own isError answer, which the agent sees as is.
type toolError string

func (e toolError) Error() string { return string(e) }

// safe keeps what an agent and the activity page may see: the upstream's own
// error text, a missing or rejected login, or a fixed sentence. The raw error
// can name the address a host resolves to, or the resolver, so it is only logged.
func (i *integration) safe(tool string, err error) error {
	var te toolError
	switch {
	case err == nil, errors.As(err, &te), errors.Is(err, upstream.ErrUnauthorized), errors.Is(err, tools.ErrNotConnected):
		return err
	}
	i.p.log().Warn("upstream tool call failed", "user", i.userID, "upstream", i.u.ID, "tool", tool, "err", err)
	return fmt.Errorf("%s: %s", i.u.Name, Reason(err))
}

// Reason is a fixed sentence for why talking to an upstream failed, safe to
// show to users and agents, unlike the error itself.
func Reason(err error) string {
	var netErr net.Error
	switch {
	case errors.Is(err, netguard.ErrNotPublic):
		return "This address is not on the public internet, and whoever runs valetkey has not allowed it."
	case errors.Is(err, upstream.ErrUnauthorized):
		return "The server refused this login. Check it and try again."
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr):
		return "valetkey could not reach the server. Check the address, or try again later."
	}
	return "valetkey could not talk to the server. Try again later, or check with whoever runs it."
}

func (i *integration) call(ctx context.Context, tool string, c tools.Creds, args json.RawMessage) (string, error) {
	cs, at, err := i.p.connect(ctx, i.u, c)
	if err != nil {
		return "", err
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		return "", upstreamErr(i.u, at, err)
	}
	out := flatten(res.Content)
	if res.IsError {
		if out == "" {
			out = "the upstream reported an error"
		}
		return "", toolError(out)
	}
	return out, nil
}

// flatten keeps text and replaces any other content with a note naming its type.
func flatten(content []mcp.Content) string {
	parts := make([]string, 0, len(content))
	for _, c := range content {
		switch c := c.(type) {
		case *mcp.TextContent:
			parts = append(parts, c.Text)
		case *mcp.ImageContent:
			parts = append(parts, "[image content omitted]")
		case *mcp.AudioContent:
			parts = append(parts, "[audio content omitted]")
		case *mcp.ResourceLink:
			parts = append(parts, "[resource_link content omitted]")
		case *mcp.EmbeddedResource:
			parts = append(parts, "[resource content omitted]")
		default:
			parts = append(parts, fmt.Sprintf("[%T content omitted]", c))
		}
	}
	return strings.Join(parts, "\n")
}
