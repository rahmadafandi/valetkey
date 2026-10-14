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
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rahmadafandi/valetkey/internal/creds"
	"github.com/rahmadafandi/valetkey/internal/netguard"
	"github.com/rahmadafandi/valetkey/internal/store"
	"github.com/rahmadafandi/valetkey/internal/tools"
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
			out = append(out, &integration{p: p, u: r.Upstream})
			cur = out[len(out)-1].(*integration)
		}
		cur.tools = append(cur.tools, r.Tool)
	}
	return out, nil
}

type integration struct {
	p     *Proxy
	u     store.Upstream
	tools []store.UpstreamTool
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
		out = append(out, tools.Tool{
			Name: name, Description: row.Description, Schema: schema,
			Destructive: row.Writes, Unscoped: true,
			Run: i.caller(row.Name),
		})
	}
	return out
}

// caller opens a session per call: initialize, tools/call with the upstream's own name, close.
// ponytail: two round trips per call; pool sessions per (user, upstream) if latency matters.
func (i *integration) caller(tool string) func(ctx context.Context, c tools.Creds, args json.RawMessage) (string, error) {
	return func(ctx context.Context, c tools.Creds, args json.RawMessage) (string, error) {
		if len(args) == 0 || string(args) == "null" {
			args = json.RawMessage("{}")
		}
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
			return "", errors.New(out)
		}
		return out, nil
	}
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
