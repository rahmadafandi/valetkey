package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rahmadafandi/valetkey/internal/store"
	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/upstream"
	"github.com/rahmadafandi/valetkey/internal/version"
)

const (
	// MaxTools is how many tools one upstream may contribute.
	MaxTools = 200
	// maxPages stops an upstream that keeps handing out cursors.
	maxPages = 50
)

var connectTimeout = 10 * time.Second

var toolNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ToolName is the name agents see for an upstream's tool, and whether it is usable.
func ToolName(upstreamName, tool string) (string, bool) {
	name := upstreamName + "__" + tool
	return name, tool != "" && toolNameRE.MatchString(name)
}

// Writes treats a tool as changing things unless its annotations say it only reads.
func Writes(a *mcp.ToolAnnotations) bool {
	if a == nil {
		return true
	}
	if a.DestructiveHint != nil && *a.DestructiveHint {
		return true
	}
	return !a.ReadOnlyHint
}

// Candidate is a tool as fetched from an upstream, waiting for the user's approval.
type Candidate struct {
	Name        string          `json:"name"` // the upstream's own name
	Prefixed    string          `json:"prefixed"`
	Description string          `json:"description"`
	Schema      json.RawMessage `json:"schema"`
	Writes      bool            `json:"writes"`
}

// Skipped is a tool the upstream listed that valetkey will not offer.
type Skipped struct {
	Name, Reason string
}

type authTransport struct {
	base          http.RoundTripper
	origin        *url.URL // the credential is only ever sent here
	header, value string
	unauthorized  atomic.Bool
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func (a *authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if a.header != "" && sameOrigin(r.URL, a.origin) {
		r = r.Clone(r.Context())
		r.Header.Set(a.header, a.value)
	}
	resp, err := a.base.RoundTrip(r)
	// Only 401: a 403 can be insufficient_scope for one tool, not a rejected login.
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		a.unauthorized.Store(true)
	}
	return resp, err
}

// upstreamErr names the upstream and marks a rejected credential with upstream.ErrUnauthorized.
func upstreamErr(u store.Upstream, at *authTransport, err error) error {
	if at.unauthorized.Load() {
		return fmt.Errorf("%s: %w", u.Name, upstream.ErrUnauthorized)
	}
	return fmt.Errorf("%s: %w", u.Name, err)
}

// connect runs initialize against the upstream with its own credential, never the caller's.
func (p *Proxy) connect(ctx context.Context, u store.Upstream, c tools.Creds) (*mcp.ClientSession, *authTransport, error) {
	endpoint, err := p.Guard.CheckURL(u.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", u.Name, err)
	}
	guarded := p.Guard.Client()
	at := &authTransport{base: guarded.Transport, origin: endpoint}
	switch u.Auth {
	case "token":
		at.header, at.value = c["header"], c["value"]
		if at.header == "" {
			at.header = "Authorization"
		}
	case "oauth":
		// A sign-in still in progress holds a verifier, not a login.
		if c["pending"] != "" {
			return nil, nil, fmt.Errorf("%s: %w", u.Name, tools.ErrNotConnected)
		}
		if c["access_token"] != "" {
			at.header, at.value = "Authorization", "Bearer "+c["access_token"]
		}
	}
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	// An empty set, not nil: nil makes the SDK advertise roots.
	client := mcp.NewClient(&mcp.Implementation{Name: "valetkey", Version: version.String()},
		&mcp.ClientOptions{Capabilities: &mcp.ClientCapabilities{}})
	checkRedirect := func(req *http.Request, via []*http.Request) error {
		if !sameOrigin(req.URL, endpoint) {
			return fmt.Errorf("refusing a redirect away from %s", endpoint.Host)
		}
		return guarded.CheckRedirect(req, via)
	}
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             u.URL,
		HTTPClient:           &http.Client{Transport: at, CheckRedirect: checkRedirect},
		MaxRetries:           -1,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		return nil, nil, upstreamErr(u, at, err)
	}
	return cs, at, nil
}

// Fetch lists the upstream's tools for review. Tools past MaxTools, with
// unusable names, or listed twice come back in Skipped.
func (p *Proxy) Fetch(ctx context.Context, u store.Upstream, c tools.Creds) ([]Candidate, []Skipped, error) {
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	cs, at, err := p.connect(ctx, u, c)
	if err != nil {
		return nil, nil, err
	}
	defer cs.Close()

	var kept []Candidate
	var skipped []Skipped
	seen := map[string]bool{}
	cursor := ""
	for page := 0; ; page++ {
		if page == maxPages {
			return nil, nil, fmt.Errorf("%s: tools/list returned more than %d pages", u.Name, maxPages)
		}
		res, err := cs.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, nil, upstreamErr(u, at, err)
		}
		// The SDK client has already dropped tools with invalid x-mcp-header annotations.
		for _, t := range res.Tools {
			prefixed, ok := ToolName(u.Name, t.Name)
			switch {
			case !ok:
				skipped = append(skipped, Skipped{t.Name, fmt.Sprintf("%q is not a usable tool name: it must match [A-Za-z0-9_-] and be at most 64 characters", prefixed)})
				continue
			case seen[t.Name]:
				skipped = append(skipped, Skipped{t.Name, "the upstream lists this name more than once"})
				continue
			case len(kept) == MaxTools:
				skipped = append(skipped, Skipped{t.Name, fmt.Sprintf("over the limit of %d tools per upstream", MaxTools)})
				continue
			}
			seen[t.Name] = true
			schema, err := canonical(t.InputSchema)
			if err != nil {
				skipped = append(skipped, Skipped{t.Name, "its input schema is not a JSON object schema"})
				continue
			}
			kept = append(kept, Candidate{Name: t.Name, Prefixed: prefixed, Description: t.Description, Schema: schema, Writes: Writes(t.Annotations)})
		}
		if res.NextCursor == "" {
			return kept, skipped, nil
		}
		cursor = res.NextCursor
	}
}

// canonical re-encodes a schema with sorted keys, so equal schemas compare equal byte for byte.
// It refuses anything but an object schema, which the SDK's AddTool panics on.
func canonical(v any) (json.RawMessage, error) {
	if raw, ok := v.(json.RawMessage); ok {
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
	}
	if v == nil {
		return json.RawMessage(`{"type":"object"}`), nil
	}
	if m, ok := v.(map[string]any); !ok || m["type"] != "object" {
		return nil, errors.New(`schema is not a JSON object with "type": "object"`)
	}
	return json.Marshal(v)
}

func sameSchema(a string, b json.RawMessage) bool {
	ca, err1 := canonical(json.RawMessage(a))
	cb, err2 := canonical(b)
	return err1 == nil && err2 == nil && bytes.Equal(ca, cb)
}

func sorted(cs []Candidate) []Candidate {
	out := slices.Clone(cs)
	slices.SortFunc(out, func(a, b Candidate) int { return strings.Compare(a.Name, b.Name) })
	return out
}
