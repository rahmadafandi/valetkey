// Package tools turns integrations into one MCP server and serves it over HTTP.
package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"
	"unicode/utf8"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rahmadafandi/valetkey/internal/store"
	"github.com/rahmadafandi/valetkey/internal/upstream"
)

// Creds are one user's decrypted credentials for one system, keyed by Field.Name.
type Creds map[string]string

type Field struct {
	Name     string // form and storage key, e.g. "token"
	Label    string
	Secret   bool // rendered as a password input
	Optional bool
}

type Tool struct {
	Name        string
	Description string
	Schema      map[string]any
	Destructive bool          // mutates the upstream; clients should confirm first
	Timeout     time.Duration // 0 means DefaultTimeout
	Run         func(ctx context.Context, c Creds, args json.RawMessage) (string, error)
}

// Integration is one upstream system, such as Jenkins.
type Integration interface {
	System() string  // "jenkins": URL path segment and storage key
	Title() string   // "Jenkins"
	Fields() []Field // credential form; empty means no credentials are needed
	Validate(ctx context.Context, c Creds) error
	Tools() []Tool
}

// Helper is implemented by integrations that explain, step by step, where a
// user finds the values their credential form asks for.
type Helper interface{ Help() []string }

type LoadCreds func(ctx context.Context, userID, system string) (Creds, error)

var ErrNotConnected = errors.New("not connected")

const (
	DefaultTimeout = 30 * time.Second
	MaxOutput      = 100 * 1024
)

var auditTimeout = 5 * time.Second

// Audit stores every tool call and answers write-budget questions.
type Audit interface {
	RecordCall(ctx context.Context, c store.ToolCall) error
	CountWrites(ctx context.Context, tokenID string, since time.Time) (int, error)
}

// RestrictionKey is the TokenInfo.Extra key carrying a personal access token's *Restriction.
const RestrictionKey = "restriction"

// RestrictionOf returns the restriction on a caller's token, or nil for an OAuth token.
func RestrictionOf(ti *mcpauth.TokenInfo) *Restriction {
	if ti == nil {
		return nil
	}
	r, _ := ti.Extra[RestrictionKey].(*Restriction)
	return r
}

// NewServer registers every integration's tools, or only those r allows when r is not nil.
func NewServer(ints []Integration, load LoadCreds, publicURL string, log *slog.Logger, audit Audit, r *Restriction) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "valetkey", Version: "0.1.0"}, nil)
	for _, in := range ints {
		for _, t := range in.Tools() {
			if r == nil || r.Allows(t.Name) {
				srv.AddTool(toolDef(t), handler(in, t, load, publicURL, log, audit))
			}
		}
	}
	return srv
}

func toolDef(t Tool) *mcp.Tool {
	destructive := t.Destructive
	return &mcp.Tool{
		Name: t.Name, Description: t.Description, InputSchema: t.Schema,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: !destructive, DestructiveHint: &destructive},
	}
}

func handler(in Integration, t Tool, load LoadCreds, publicURL string, log *slog.Logger, audit Audit) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		var userID, email string
		if ti := req.Extra.TokenInfo; ti != nil {
			userID = ti.UserID
			email, _ = ti.Extra["email"].(string)
		}
		r := RestrictionOf(req.Extra.TokenInfo)
		var out string
		var err error
		var dryRun bool
		switch {
		case r != nil && !r.Allows(t.Name):
			err = Refuse("%s: not allowed for this token", t.Name)
		case r != nil:
			err = r.Scope.Check(in, t.Name, req.Params.Arguments)
			if err == nil && t.Destructive && r.MaxWritesPerHour > 0 && audit != nil {
				// Counted before this call is recorded, so concurrent calls can overshoot by a few.
				n, cerr := audit.CountWrites(ctx, r.TokenID, time.Now().Add(-time.Hour))
				switch {
				case cerr != nil:
					log.Error("count writes", "token", r.Name, "err", cerr)
					err = fmt.Errorf("%s: could not check this token's write limit (internal error)", t.Name)
				case n >= r.MaxWritesPerHour:
					err = Refuse("%s: write limit of %d/hour reached for this token", t.Name, r.MaxWritesPerHour)
				}
			}
			switch {
			case err != nil:
			case t.Destructive && r.DryRun:
				out, dryRun = fmt.Sprintf("dry-run: would call %s with %s", t.Name, truncate(string(req.Params.Arguments), 1024)), true
			default:
				out, err = run(ctx, in, t, load, userID, req.Params.Arguments, log)
			}
		default:
			out, err = run(ctx, in, t, load, userID, req.Params.Arguments, log)
		}
		connectURL := publicURL + "/connect/" + in.System()
		switch {
		case errors.Is(err, ErrNotConnected):
			out = fmt.Sprintf("%s is not connected. Connect it at %s", in.Title(), connectURL)
		case errors.Is(err, upstream.ErrUnauthorized):
			out = fmt.Sprintf("%s rejected your credentials (%v). Reconnect at %s", in.Title(), err, connectURL)
		case err != nil:
			out = err.Error()
		}
		via := "oauth"
		if r != nil {
			via = "token:" + r.Name
		}
		log.Info("tool call", "user", email, "via", via, "tool", t.Name, "args", truncate(string(req.Params.Arguments), 1024),
			"ok", err == nil, "ms", time.Since(start).Milliseconds())
		if audit != nil && userID != "" {
			outcome := "ok"
			switch {
			case dryRun:
				outcome = "dry_run"
			case IsRefusal(err):
				outcome = "refused"
			case err != nil:
				outcome = "error"
			}
			c := store.ToolCall{UserID: userID, Tool: t.Name, IsWrite: t.Destructive, Outcome: outcome,
				Args: truncate(string(req.Params.Arguments), 4096), MS: time.Since(start).Milliseconds()}
			if err != nil {
				c.Message = truncate(err.Error(), 1024)
			}
			if r != nil {
				c.TokenID, c.TokenName = r.TokenID, r.Name
			}
			// A cancelled request must not drop the record of a call that already ran,
			// and a stalled database must not hold the response.
			actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
			aerr := audit.RecordCall(actx, c)
			cancel()
			if aerr != nil {
				log.Error("audit record failed", "tool", t.Name, "err", aerr)
			}
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: truncate(out, MaxOutput)}},
			IsError: err != nil,
		}, nil
	}
}

func run(ctx context.Context, in Integration, t Tool, load LoadCreds, userID string, args json.RawMessage, log *slog.Logger) (out string, err error) {
	if userID == "" {
		return "", errors.New("unauthenticated")
	}
	var c Creds
	if len(in.Fields()) > 0 {
		var err error
		if c, err = load(ctx, userID, in.System()); err != nil {
			if errors.Is(err, ErrNotConnected) {
				return "", err
			}
			log.Error("load credentials", "user", userID, "system", in.System(), "err", err)
			return "", fmt.Errorf("%s: could not load your credentials (internal error)", in.Title())
		}
	}
	timeout := t.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			log.Error("tool panic", "tool", t.Name, "panic", r)
			out, err = "", fmt.Errorf("%s: internal error", t.Name)
		}
	}()
	out, err = t.Run(ctx, c, args)
	if errors.Is(err, context.DeadlineExceeded) {
		return "", fmt.Errorf("%s timed out after %s", t.Name, timeout)
	}
	return out, err
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + fmt.Sprintf("\n[truncated: %d bytes omitted]", len(s)-cut)
}

// HTTPHandler serves srv over stateless Streamable HTTP behind bearer-token auth.
// Unauthenticated requests get 401 with WWW-Authenticate pointing at resourceMetadataURL.
// A personal access token gets a server holding only its allowed tools, so
// tools/list shows just those.
func HTTPHandler(ints []Integration, load LoadCreds, publicURL string, log *slog.Logger, audit Audit, verify mcpauth.TokenVerifier, resourceMetadataURL string) http.Handler {
	full := NewServer(ints, load, publicURL, log, audit, nil)
	h := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		// ponytail: a restricted server is rebuilt per request; cache by token if this shows up in profiles.
		if r := RestrictionOf(mcpauth.TokenInfoFromContext(req.Context())); r != nil {
			return NewServer(ints, load, publicURL, log, audit, r)
		}
		return full
	},
		// /mcp requires a bearer token and is never a local server, so the SDK's
		// DNS-rebinding check (which 403s a non-localhost Host on a loopback
		// connection) only breaks same-host reverse proxies.
		&mcp.StreamableHTTPOptions{Stateless: true, DisableLocalhostProtection: true})
	return mcpauth.RequireBearerToken(verify, &mcpauth.RequireBearerTokenOptions{ResourceMetadataURL: resourceMetadataURL})(h)
}

// Args decodes tool arguments; missing arguments decode as an empty object.
func Args(raw json.RawMessage, v any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}
	return nil
}

func Object(props map[string]any, required ...string) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func Str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func Int(desc string) map[string]any { return map[string]any{"type": "integer", "description": desc} }
