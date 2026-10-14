package tools

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rahmadafandi/valetkey/internal/store"
	"github.com/rahmadafandi/valetkey/internal/upstream"
)

type fake struct{}

func (fake) System() string                              { return "fake" }
func (fake) Title() string                               { return "Fake" }
func (fake) Fields() []Field                             { return []Field{{Name: "token", Label: "Token", Secret: true}} }
func (fake) Validate(context.Context, Creds) error       { return nil }
func (fake) ScopeKey() string                            { return "fake" }
func (fake) ParseScope(raw json.RawMessage) (any, error) { return StringOrList(raw) }

// CheckScope fences bitbucket_fake by its repo argument and lets the other tools through.
func (fake) CheckScope(scope any, tool string, args json.RawMessage) error {
	if tool != "bitbucket_fake" {
		return nil
	}
	var a struct{ Repo string }
	json.Unmarshal(args, &a)
	if !slices.Contains(scope.([]string), a.Repo) {
		return Refuse("%s: repository %q is outside this token's scope", tool, a.Repo)
	}
	return nil
}
func (fake) Tools() []Tool {
	return []Tool{
		{Name: "fake_echo", Description: "echo", Schema: Object(map[string]any{"msg": Str("message")}),
			Run: func(_ context.Context, c Creds, raw json.RawMessage) (string, error) {
				var a struct {
					Msg string `json:"msg"`
				}
				if err := Args(raw, &a); err != nil {
					return "", err
				}
				return c["token"] + ":" + a.Msg, nil
			}},
		{Name: "bitbucket_fake", Description: "scoped by repo", Schema: Object(map[string]any{"repo": Str("repo")}),
			Run: func(context.Context, Creds, json.RawMessage) (string, error) { return "reached", nil }},
		{Name: "fake_deploy", Description: "deploy", Schema: Object(nil), Destructive: true,
			Run: func(context.Context, Creds, json.RawMessage) (string, error) { return "deployed", nil }},
		{Name: "fake_unauth", Description: "unauth", Schema: Object(nil),
			Run: func(context.Context, Creds, json.RawMessage) (string, error) {
				return "", upstream.StatusErr("fake", 401, []byte("bad token"))
			}},
		{Name: "fake_big", Description: "big", Schema: Object(nil),
			Run: func(context.Context, Creds, json.RawMessage) (string, error) {
				return strings.Repeat("x", MaxOutput+500), nil
			}},
		{Name: "fake_panic", Description: "panic", Schema: Object(nil),
			Run: func(context.Context, Creds, json.RawMessage) (string, error) { panic("boom") }},
		{Name: "fake_slow", Description: "slow", Schema: Object(nil), Timeout: 50 * time.Millisecond,
			Run: func(ctx context.Context, _ Creds, _ json.RawMessage) (string, error) {
				<-ctx.Done()
				return "", ctx.Err()
			}},
	}
}

const metaURL = "https://center.test/.well-known/oauth-protected-resource"

func serve(t *testing.T) string { return serveAudit(t, nil) }

func serveAudit(t *testing.T, audit Audit) string {
	load := func(_ context.Context, userID, system string) (Creds, error) {
		if userID == "u3" {
			return nil, errors.New("pq: connection refused to 10.0.0.5")
		}
		if userID == "u1" && system == "fake" {
			return Creds{"token": "secret1"}, nil
		}
		return nil, ErrNotConnected
	}
	verify := func(_ context.Context, tok string, _ *http.Request) (*mcpauth.TokenInfo, error) {
		users := map[string]string{"t1": "u1", "t2": "u2", "t3": "u3"}
		if tok == "pat" {
			return &mcpauth.TokenInfo{UserID: "u1", Expiration: time.Now().Add(time.Hour), Extra: map[string]any{
				"email":        "u1@example.com",
				RestrictionKey: &Restriction{Name: "atlas", Tools: []string{"fake_echo", "bitbucket_fake"}, Scope: Scope{"fake": []string{"acme/web"}}},
			}}, nil
		}
		if id, ok := users[tok]; ok {
			return &mcpauth.TokenInfo{UserID: id, Expiration: time.Now().Add(time.Hour),
				Extra: map[string]any{"email": id + "@example.com"}}, nil
		}
		return nil, mcpauth.ErrInvalidToken
	}
	ts := httptest.NewServer(HTTPHandler([]Integration{fake{}}, load, "https://center.test", slog.New(slog.DiscardHandler), audit, verify, metaURL))
	t.Cleanup(ts.Close)
	return ts.URL
}

type bearer string

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+string(b))
	return http.DefaultTransport.RoundTrip(r)
}

func connect(t *testing.T, url, token string) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	cs, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint: url, HTTPClient: &http.Client{Transport: bearer(token)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return res.Content[0].(*mcp.TextContent).Text, res.IsError
}

func TestNoTokenIs401WithMetadata(t *testing.T) {
	url := serve(t)
	resp, err := http.Post(url, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), `resource_metadata="`+metaURL+`"`) {
		t.Errorf("status=%d www-authenticate=%q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
}

func TestCallWithCreds(t *testing.T) {
	cs := connect(t, serve(t), "t1")
	if text, isErr := call(t, cs, "fake_echo", map[string]any{"msg": "hi"}); isErr || text != "secret1:hi" {
		t.Errorf("got %q isErr=%v", text, isErr)
	}
}

func TestNotConnected(t *testing.T) {
	cs := connect(t, serve(t), "t2")
	text, isErr := call(t, cs, "fake_echo", map[string]any{"msg": "hi"})
	if !isErr || text != "Fake is not connected. Connect it at https://center.test/connect/fake" {
		t.Errorf("got %q isErr=%v", text, isErr)
	}
}

func TestUpstreamUnauthorized(t *testing.T) {
	cs := connect(t, serve(t), "t1")
	text, isErr := call(t, cs, "fake_unauth", nil)
	if !isErr || !strings.HasPrefix(text, "Fake rejected your credentials") || !strings.HasSuffix(text, "Reconnect at https://center.test/connect/fake") {
		t.Errorf("got %q isErr=%v", text, isErr)
	}
}

func TestOutputTruncated(t *testing.T) {
	cs := connect(t, serve(t), "t1")
	text, _ := call(t, cs, "fake_big", nil)
	if !strings.HasSuffix(text, "[truncated: 500 bytes omitted]") || len(text) > MaxOutput+100 {
		t.Errorf("len=%d tail=%q", len(text), text[len(text)-40:])
	}
}

func TestTimeout(t *testing.T) {
	cs := connect(t, serve(t), "t1")
	if text, isErr := call(t, cs, "fake_slow", nil); !isErr || !strings.Contains(text, "timed out") {
		t.Errorf("got %q isErr=%v", text, isErr)
	}
}

func TestAnnotations(t *testing.T) {
	cs := connect(t, serve(t), "t1")
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.Tools {
		switch tl.Name {
		case "fake_deploy":
			if tl.Annotations.ReadOnlyHint || tl.Annotations.DestructiveHint == nil || !*tl.Annotations.DestructiveHint {
				t.Errorf("fake_deploy annotations = %+v", tl.Annotations)
			}
		case "fake_echo":
			if !tl.Annotations.ReadOnlyHint {
				t.Errorf("fake_echo annotations = %+v", tl.Annotations)
			}
		}
	}
}

func TestNonLocalHostBehindLoopbackProxy(t *testing.T) {
	url := serve(t) // listens on 127.0.0.1
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Host = "mcp.example.com"
	req.Header.Set("Authorization", "Bearer t1")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestPanicIsRecovered(t *testing.T) {
	cs := connect(t, serve(t), "t1")
	if text, isErr := call(t, cs, "fake_panic", nil); !isErr || text != "fake_panic: internal error" {
		t.Errorf("got %q isErr=%v", text, isErr)
	}
	if text, isErr := call(t, cs, "fake_echo", map[string]any{"msg": "hi"}); isErr || text != "secret1:hi" {
		t.Errorf("after panic: got %q isErr=%v", text, isErr)
	}
}

func TestLoadErrorIsNotLeaked(t *testing.T) {
	cs := connect(t, serve(t), "t3")
	text, isErr := call(t, cs, "fake_echo", map[string]any{"msg": "hi"})
	if !isErr || text != "Fake: could not load your credentials (internal error)" {
		t.Errorf("got %q isErr=%v", text, isErr)
	}
}

func TestRestrictedTokenSeesOnlyAllowedTools(t *testing.T) {
	cs := connect(t, serve(t), "pat")
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	if strings.Join(names, ",") != "bitbucket_fake,fake_echo" {
		t.Errorf("tools/list = %v", names)
	}
	if res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "fake_deploy"}); err == nil && !res.IsError {
		t.Error("a tool outside the token's list ran")
	}
	if text, isErr := call(t, cs, "fake_echo", map[string]any{"msg": "hi"}); isErr || text != "secret1:hi" {
		t.Errorf("allowed tool: %q isErr=%v", text, isErr)
	}
}

func TestRestrictedTokenScope(t *testing.T) {
	cs := connect(t, serve(t), "pat")
	if text, isErr := call(t, cs, "bitbucket_fake", map[string]any{"repo": "acme/web"}); isErr || text != "reached" {
		t.Errorf("in scope: %q isErr=%v", text, isErr)
	}
	if text, isErr := call(t, cs, "bitbucket_fake", map[string]any{"repo": "acme/other"}); !isErr || !strings.HasPrefix(text, "refused:") {
		t.Errorf("out of scope: %q isErr=%v", text, isErr)
	}
}

func TestOAuthTokenSeesAllTools(t *testing.T) {
	cs := connect(t, serve(t), "t1")
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil || len(res.Tools) != len(fake{}.Tools()) {
		t.Fatalf("tools/list: %d %v", len(res.Tools), err)
	}
}

func TestHandlerRefusesToolOutsideTokenList(t *testing.T) {
	deploy := fake{}.Tools()[2]
	h := handler(fake{}, deploy, nil, "https://center.test", slog.New(slog.DiscardHandler), nil)
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: deploy.Name}, Extra: &mcp.RequestExtra{
		TokenInfo: &mcpauth.TokenInfo{UserID: "u1", Extra: map[string]any{RestrictionKey: &Restriction{Name: "atlas", Tools: []string{"fake_echo"}}}},
	}}
	res, err := h(context.Background(), req)
	if err != nil || !res.IsError {
		t.Fatalf("%+v %v", res, err)
	}
	if text := res.Content[0].(*mcp.TextContent).Text; text != "refused: fake_deploy: not allowed for this token" {
		t.Errorf("text = %q", text)
	}
}

type fakeAudit struct {
	calls  []store.ToolCall
	writes int
	fail   bool
}

func (f *fakeAudit) RecordCall(_ context.Context, c store.ToolCall) error {
	if f.fail {
		return errors.New("db down")
	}
	f.calls = append(f.calls, c)
	return nil
}

func (f *fakeAudit) CountWrites(context.Context, string, time.Time) (int, error) {
	return f.writes, nil
}

func TestAuditRecordsOAuthCall(t *testing.T) {
	a := &fakeAudit{}
	cs := connect(t, serveAudit(t, a), "t1")
	call(t, cs, "fake_deploy", nil)
	call(t, cs, "fake_echo", map[string]any{"msg": "hi"})
	if len(a.calls) != 2 {
		t.Fatalf("calls = %+v", a.calls)
	}
	d, e := a.calls[0], a.calls[1]
	if d.Outcome != "ok" || d.TokenID != "" || d.Tool != "fake_deploy" || !d.IsWrite || d.UserID != "u1" || d.MS < 0 {
		t.Errorf("deploy row = %+v", d)
	}
	if e.IsWrite || e.Args != `{"msg":"hi"}` {
		t.Errorf("echo row = %+v", e)
	}
}

func TestAuditRecordsRefusal(t *testing.T) {
	a := &fakeAudit{}
	cs := connect(t, serveAudit(t, a), "pat")
	if _, isErr := call(t, cs, "bitbucket_fake", map[string]any{"repo": "acme/other"}); !isErr {
		t.Fatal("expected refusal")
	}
	if len(a.calls) != 1 {
		t.Fatalf("calls = %+v", a.calls)
	}
	c := a.calls[0]
	if c.Outcome != "refused" || !strings.HasPrefix(c.Message, "refused: ") || c.TokenName != "atlas" {
		t.Errorf("row = %+v", c)
	}
}

func TestAuditRecordsUpstreamError(t *testing.T) {
	a := &fakeAudit{}
	cs := connect(t, serveAudit(t, a), "t1")
	call(t, cs, "fake_unauth", nil)
	if len(a.calls) != 1 || a.calls[0].Outcome != "error" || a.calls[0].Message == "" {
		t.Errorf("calls = %+v", a.calls)
	}
}

func TestAuditFailureDoesNotFailCall(t *testing.T) {
	cs := connect(t, serveAudit(t, &fakeAudit{fail: true}), "t1")
	if text, isErr := call(t, cs, "fake_echo", map[string]any{"msg": "hi"}); isErr || text != "secret1:hi" {
		t.Errorf("%q isErr=%v", text, isErr)
	}
}

func TestAuditTruncatesArgsAndMessage(t *testing.T) {
	a := &fakeAudit{}
	cs := connect(t, serveAudit(t, a), "pat")
	call(t, cs, "bitbucket_fake", map[string]any{"repo": strings.Repeat("r", 6000)})
	c := a.calls[0]
	if len(c.Args) > 4096+60 || !strings.Contains(c.Args, "[truncated") {
		t.Errorf("args len %d", len(c.Args))
	}
	if len(c.Message) > 1024+60 || !strings.Contains(c.Message, "[truncated") {
		t.Errorf("message len %d", len(c.Message))
	}
}
