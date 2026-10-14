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
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rahmadafandi/valetkey/internal/store"
	"github.com/rahmadafandi/valetkey/internal/upstream"
)

type fake struct{}

// deploys and echoes count the calls that reached a tool's Run.
var deploys, echoes atomic.Int32

func (fake) System() string                              { return "fake" }
func (fake) Title() string                               { return "Fake" }
func (fake) Fields() []Field                             { return []Field{{Name: "token", Label: "Token", Secret: true}} }
func (fake) Validate(context.Context, Creds) error       { return nil }
func (fake) ScopeKey() string                            { return "fake" }
func (fake) ParseScope(raw json.RawMessage) (any, error) { return StringOrList(raw) }

// CheckScope fences bitbucket_fake by its repo argument and lets the other tools through.
func (fake) CheckScope(scope any, tool string, args json.RawMessage) error {
	if tool != "bitbucket_fake" && tool != "bitbucket_write" {
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
				echoes.Add(1)
				return c["token"] + ":" + a.Msg, nil
			}},
		{Name: "bitbucket_fake", Description: "scoped by repo", Schema: Object(map[string]any{"repo": Str("repo")}),
			Run: func(context.Context, Creds, json.RawMessage) (string, error) { return "reached", nil }},
		{Name: "fake_deploy", Description: "deploy", Schema: Object(nil), Destructive: true,
			Run: func(context.Context, Creds, json.RawMessage) (string, error) {
				deploys.Add(1)
				return "deployed", nil
			}},
		{Name: "bitbucket_write", Description: "scoped write", Schema: Object(map[string]any{"repo": Str("repo")}), Destructive: true,
			Run: func(context.Context, Creds, json.RawMessage) (string, error) {
				deploys.Add(1)
				return "written", nil
			}},
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

var budgets = map[string]struct {
	max int
	dry bool
}{"cap3": {3, false}, "unlimited": {0, false}, "dry": {0, true}}

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
		if budget, ok := budgets[tok]; ok {
			return &mcpauth.TokenInfo{UserID: "u1", Expiration: time.Now().Add(time.Hour), Extra: map[string]any{
				"email":        "u1@example.com",
				RestrictionKey: &Restriction{TokenID: "tok1", Name: tok, Tools: []string{"fake_echo", "fake_deploy", "bitbucket_write"}, Scope: Scope{"fake": []string{"acme/web"}}, MaxWritesPerHour: budget.max, DryRun: budget.dry},
			}}, nil
		}
		if id, ok := users[tok]; ok {
			return &mcpauth.TokenInfo{UserID: id, Expiration: time.Now().Add(time.Hour),
				Extra: map[string]any{"email": id + "@example.com"}}, nil
		}
		return nil, mcpauth.ErrInvalidToken
	}
	ts := httptest.NewServer(HTTPHandler([]Integration{fake{}}, nil, load, "https://center.test", slog.New(slog.DiscardHandler), audit, verify, metaURL))
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
	block  bool
}

func (f *fakeAudit) RecordCall(ctx context.Context, c store.ToolCall) error {
	if f.block {
		<-ctx.Done()
		return ctx.Err()
	}
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

func TestAuditStallDoesNotHangCall(t *testing.T) {
	old := auditTimeout
	auditTimeout = 100 * time.Millisecond
	t.Cleanup(func() { auditTimeout = old })
	cs := connect(t, serveAudit(t, &fakeAudit{block: true}), "t1")
	done := make(chan struct{})
	go func() {
		defer close(done)
		if text, isErr := call(t, cs, "fake_echo", map[string]any{"msg": "hi"}); isErr || text != "secret1:hi" {
			t.Errorf("%q isErr=%v", text, isErr)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("call hung on a stalled audit write")
	}
}

func TestAuditTruncationKeepsValidUTF8(t *testing.T) {
	a := &fakeAudit{}
	cs := connect(t, serveAudit(t, a), "pat")
	call(t, cs, "bitbucket_fake", map[string]any{"repo": strings.Repeat("日", 3000)})
	c := a.calls[0]
	if !utf8.ValidString(c.Args) || !utf8.ValidString(c.Message) || !strings.Contains(c.Args, "[truncated") {
		t.Errorf("args valid=%v message valid=%v", utf8.ValidString(c.Args), utf8.ValidString(c.Message))
	}
}

func TestWriteBudget(t *testing.T) {
	cases := []struct {
		name, token string
		writes      int
		refused     bool
	}{
		{"at the limit", "cap3", 3, true},
		{"under the limit", "cap3", 2, false},
		{"unlimited", "unlimited", 1000, false},
		{"oauth caller", "t1", 1000, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			deploys.Store(0)
			cs := connect(t, serveAudit(t, &fakeAudit{writes: c.writes}), c.token)
			text, isErr := call(t, cs, "fake_deploy", nil)
			if c.refused {
				if !isErr || !strings.HasPrefix(text, "refused: fake_deploy: ") || !strings.Contains(text, "write limit of 3/hour reached") || deploys.Load() != 0 {
					t.Errorf("text = %q isErr = %v deploys = %d", text, isErr, deploys.Load())
				}
				echoes.Store(0)
				if _, isErr := call(t, cs, "fake_echo", map[string]any{"msg": "x"}); isErr || echoes.Load() != 1 {
					t.Error("a read tool must ignore the write limit")
				}
			} else if isErr || deploys.Load() != 1 {
				t.Errorf("text = %q isErr = %v deploys = %d", text, isErr, deploys.Load())
			}
		})
	}
}

func TestDryRun(t *testing.T) {
	deploys.Store(0)
	echoes.Store(0)
	a := &fakeAudit{}
	cs := connect(t, serveAudit(t, a), "dry")
	text, isErr := call(t, cs, "fake_deploy", nil)
	if isErr || !strings.HasPrefix(text, "dry-run: would call fake_deploy with ") || deploys.Load() != 0 {
		t.Fatalf("text = %q isErr = %v deploys = %d", text, isErr, deploys.Load())
	}
	if len(a.calls) != 1 || a.calls[0].Outcome != "dry_run" || !a.calls[0].IsWrite {
		t.Errorf("calls = %+v", a.calls)
	}
	if _, isErr := call(t, cs, "fake_echo", map[string]any{"msg": "x"}); isErr || echoes.Load() != 1 {
		t.Error("a read tool must still run in dry-run mode")
	}
	text, isErr = call(t, cs, "bitbucket_write", map[string]any{"repo": "acme/other"})
	if !isErr || !strings.HasPrefix(text, "refused: ") || deploys.Load() != 0 {
		t.Errorf("out-of-scope write in dry run: %q isErr = %v", text, isErr)
	}
}

func TestWriteLimitHoldsUnderParallelCalls(t *testing.T) {
	s := store.OpenTest(t)
	u, err := s.UpsertUser(context.Background(), "par@example.com")
	if err != nil {
		t.Fatal(err)
	}
	var ran atomic.Int32
	slow := Tool{Name: "fake_slow_deploy", Schema: Object(nil), Destructive: true,
		Run: func(context.Context, Creds, json.RawMessage) (string, error) {
			ran.Add(1)
			time.Sleep(50 * time.Millisecond)
			return "deployed", nil
		}}
	load := func(context.Context, string, string) (Creds, error) { return Creds{}, nil }
	h := handler(fake{}, slow, load, "https://center.test", slog.New(slog.DiscardHandler), s)
	const limit = 3
	r := &Restriction{TokenID: "tokpar", Name: "par", Tools: []string{slow.Name}, Scope: Scope{"fake": []string{"acme/web"}}, MaxWritesPerHour: limit}
	var wg sync.WaitGroup
	for range limit + 5 {
		wg.Go(func() {
			req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: slow.Name}, Extra: &mcp.RequestExtra{
				TokenInfo: &mcpauth.TokenInfo{UserID: u.ID, Extra: map[string]any{RestrictionKey: r}},
			}}
			if _, err := h(context.Background(), req); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if n := ran.Load(); n != limit {
		t.Errorf("%d calls ran, want %d", n, limit)
	}
}

type elsewhere struct{ fake }

func (elsewhere) ConnectURL(publicURL string) string { return publicURL + "/upstreams" }

func TestConnectorURL(t *testing.T) {
	load := func(context.Context, string, string) (Creds, error) { return nil, ErrNotConnected }
	tl := Tool{Name: "elsewhere_echo", Run: func(context.Context, Creds, json.RawMessage) (string, error) { return "", nil }}
	h := handler(elsewhere{}, tl, load, "https://center.test", slog.New(slog.DiscardHandler), nil)
	res, err := h(context.Background(), &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Name: tl.Name},
		Extra:  &mcp.RequestExtra{TokenInfo: &mcpauth.TokenInfo{UserID: "u1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if text := res.Content[0].(*mcp.TextContent).Text; text != "Fake is not connected. Connect it at https://center.test/upstreams" {
		t.Errorf("got %q", text)
	}
}

type badSchema struct{ fake }

func (badSchema) Tools() []Tool {
	run := func(context.Context, Creds, json.RawMessage) (string, error) { return "ok", nil }
	return []Tool{
		{Name: "bad_string", Schema: map[string]any{"type": "string"}, Run: run},
		{Name: "bad_good", Schema: Object(nil), Run: run},
	}
}

func TestNewServerSkipsToolTheSDKRefuses(t *testing.T) {
	srv := NewServer([]Integration{badSchema{}}, nil, "https://center.test", slog.New(slog.DiscardHandler), nil, nil)
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil || len(res.Tools) != 1 || res.Tools[0].Name != "bad_good" {
		t.Fatalf("%v %+v", err, res)
	}
}

// proxied stands in for a user's upstream MCP server: valetkey cannot read its
// arguments, so it has no Scoper and its tools are Unscoped.
type proxied struct{ ran *atomic.Int32 }

func (proxied) System() string                        { return "upstream:p1" }
func (proxied) Title() string                         { return "github" }
func (proxied) Fields() []Field                       { return nil }
func (proxied) Validate(context.Context, Creds) error { return nil }
func (p proxied) Tools() []Tool {
	return []Tool{{Name: "a__echo", Schema: Object(nil), Destructive: true, Unscoped: true,
		Run: func(_ context.Context, _ Creds, raw json.RawMessage) (string, error) {
			p.ran.Add(1)
			return "upstream:" + string(raw), nil
		}}}
}

func TestUnscopedToolGoesThroughTheFence(t *testing.T) {
	var ran atomic.Int32
	in := proxied{&ran}
	tl := in.Tools()[0]
	callAs := func(a *fakeAudit, r *Restriction) (string, bool) {
		h := handler(in, tl, nil, "https://center.test", slog.New(slog.DiscardHandler), a)
		res, err := h(context.Background(), &mcp.CallToolRequest{
			Params: &mcp.CallToolParamsRaw{Name: tl.Name, Arguments: json.RawMessage(`{"q":1}`)},
			Extra:  &mcp.RequestExtra{TokenInfo: &mcpauth.TokenInfo{UserID: "u1", Extra: map[string]any{RestrictionKey: r}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return res.Content[0].(*mcp.TextContent).Text, res.IsError
	}
	allowed := func() *Restriction {
		return &Restriction{TokenID: "tokp", Name: "bot", Tools: []string{tl.Name}, Scope: Scope{}, MaxWritesPerHour: 3}
	}

	a := &fakeAudit{}
	if text, isErr := callAs(a, allowed()); isErr || text != `upstream:{"q":1}` || ran.Load() != 1 {
		t.Errorf("allowed: %q isErr=%v ran=%d", text, isErr, ran.Load())
	}
	no := allowed()
	no.Tools = []string{"something_else"}
	if text, isErr := callAs(a, no); !isErr || text != "refused: a__echo: not allowed for this token" || ran.Load() != 1 {
		t.Errorf("not allowed: %q isErr=%v ran=%d", text, isErr, ran.Load())
	}
	a.writes = 3
	if text, isErr := callAs(a, allowed()); !isErr || !strings.Contains(text, "write limit of 3/hour reached") || ran.Load() != 1 {
		t.Errorf("at the limit: %q isErr=%v ran=%d", text, isErr, ran.Load())
	}
	a.writes = 0
	dry := allowed()
	dry.DryRun = true
	if text, isErr := callAs(a, dry); isErr || !strings.HasPrefix(text, "dry-run: would call a__echo with ") || ran.Load() != 1 {
		t.Errorf("dry run: %q isErr=%v ran=%d", text, isErr, ran.Load())
	}
	var outcomes []string
	for _, c := range a.calls {
		if !c.IsWrite || c.Tool != tl.Name || c.TokenID != "tokp" {
			t.Errorf("audit row = %+v", c)
		}
		outcomes = append(outcomes, c.Outcome)
	}
	if strings.Join(outcomes, ",") != "ok,refused,refused,dry_run" {
		t.Errorf("audit outcomes = %v", outcomes)
	}
}

// userTools is a test-only per-user integration source: u1 has an upstream, u2 none, u3 a broken store.
func userTools(ran *atomic.Int32) UserIntegrations {
	return func(_ context.Context, userID string) ([]Integration, error) {
		switch userID {
		case "u1":
			return []Integration{proxied{ran}}, nil
		case "u3":
			return nil, errors.New("db down")
		}
		return nil, nil
	}
}

func TestUserToolsAreServedOnlyToTheirOwner(t *testing.T) {
	var ran atomic.Int32
	load := func(context.Context, string, string) (Creds, error) { return Creds{"token": "x"}, nil }
	verify := func(_ context.Context, tok string, _ *http.Request) (*mcpauth.TokenInfo, error) {
		return &mcpauth.TokenInfo{UserID: map[string]string{"t1": "u1", "t2": "u2", "t3": "u3"}[tok], Expiration: time.Now().Add(time.Hour)}, nil
	}
	ts := httptest.NewServer(HTTPHandler([]Integration{fake{}}, userTools(&ran), load, "https://center.test", slog.New(slog.DiscardHandler), nil, verify, metaURL))
	t.Cleanup(ts.Close)
	names := func(cs *mcp.ClientSession) []string {
		res, err := cs.ListTools(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, tl := range res.Tools {
			out = append(out, tl.Name)
		}
		return out
	}

	a, b, broken := connect(t, ts.URL, "t1"), connect(t, ts.URL, "t2"), connect(t, ts.URL, "t3")
	if n := names(a); !slices.Contains(n, "a__echo") || !slices.Contains(n, "fake_echo") {
		t.Errorf("A's tools/list = %v", n)
	}
	if n := names(b); slices.Contains(n, "a__echo") || !slices.Contains(n, "fake_echo") {
		t.Errorf("B's tools/list = %v", n)
	}
	if n := names(broken); slices.Contains(n, "a__echo") || !slices.Contains(n, "fake_echo") {
		t.Errorf("a failing user lookup should leave the native tools: %v", n)
	}
	if _, err := b.CallTool(context.Background(), &mcp.CallToolParams{Name: "a__echo"}); err == nil || !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("B calling A's tool: err = %v", err)
	}
	if ran.Load() != 0 {
		t.Errorf("B's call reached A's upstream %d times", ran.Load())
	}
	if text, isErr := call(t, a, "a__echo", nil); isErr || ran.Load() != 1 {
		t.Errorf("A's call: %q isErr=%v", text, isErr)
	}
}
