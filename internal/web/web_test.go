package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rahmadafandi/valetkey/internal/auth"
	"github.com/rahmadafandi/valetkey/internal/creds"
	"github.com/rahmadafandi/valetkey/internal/netguard"
	"github.com/rahmadafandi/valetkey/internal/proxy"
	"github.com/rahmadafandi/valetkey/internal/store"
	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/vault"
)

type fakeInt struct{}

func (fakeInt) System() string { return "fake" }
func (fakeInt) Title() string  { return "Fake" }
func (fakeInt) Fields() []tools.Field {
	return []tools.Field{{Name: "token", Label: "Token", Secret: true}}
}
func (fakeInt) Help() []string { return []string{"Open Fake <settings> and copy the token."} }
func (fakeInt) Validate(_ context.Context, c tools.Creds) error {
	if c["token"] != "good" {
		return errors.New("rejected by fake")
	}
	return nil
}
func (fakeInt) ScopeKey() string                              { return "fake" }
func (fakeInt) ParseScope(raw json.RawMessage) (any, error)   { return tools.StringOrList(raw) }
func (fakeInt) CheckScope(any, string, json.RawMessage) error { return nil }
func (fakeInt) Tools() []tools.Tool {
	return []tools.Tool{{Name: "loki_query", Description: "read logs"}, {Name: "jenkins_deploy", Description: "deploy", Destructive: true}}
}

type env struct {
	web    *Web
	px     *proxy.Proxy
	url    string
	creds  creds.Store
	as     *auth.Server
	user   store.User
	cookie *http.Cookie
}

func newEnv(t *testing.T) *env {
	st := store.OpenTest(t)
	v, _ := vault.New(bytes.Repeat([]byte{3}, 32))
	cr := creds.Store{DB: st, Vault: v, Log: slog.New(slog.DiscardHandler)}
	ts := httptest.NewUnstartedServer(nil)
	pub := "http://" + ts.Listener.Addr().String()
	as := &auth.Server{Store: st, Signer: auth.NewSigner([]byte(strings.Repeat("k", 32))), PublicURL: pub, SessionTTL: time.Hour,
		Integrations: []tools.Integration{fakeInt{}}}
	guard := &netguard.Guard{AllowHosts: []string{"127.0.0.1"}, Lookup: internalLookup}
	px := &proxy.Proxy{Store: st, Creds: cr, Guard: guard, PublicURL: pub, Log: slog.New(slog.DiscardHandler)}
	h := &Web{Auth: as, Creds: cr, Integrations: []tools.Integration{fakeInt{}},
		Catalog:   []CatalogEntry{{Name: "Example MCP", Description: "Inbox tools", Setup: "npx example-mcp"}},
		PublicURL: pub, Log: slog.New(slog.DiscardHandler), Proxy: px, Guard: guard, UserTools: px.Integrations}
	mux := http.NewServeMux()
	h.Routes(mux)
	mux.Handle("/mcp", tools.HTTPHandler([]tools.Integration{fakeInt{}}, px.Integrations, cr.Load, pub, slog.New(slog.DiscardHandler), st, as.Verify, as.ResourceMetadataURL()))
	ts.Config.Handler = mux
	ts.Start()
	t.Cleanup(ts.Close)
	u, err := st.UpsertUser(context.Background(), "rahmad@example.com")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	as.SetSession(rec, u)
	return &env{web: h, px: px, url: pub, creds: cr, as: as, user: u, cookie: rec.Result().Cookies()[0]}
}

var noFollow = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (e *env) get(t *testing.T, path string, signedIn bool) (int, string) {
	req, _ := http.NewRequest("GET", e.url+path, nil)
	if signedIn {
		req.AddCookie(e.cookie)
	}
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (e *env) post(t *testing.T, path string, form url.Values, origin string) (int, string) {
	req, _ := http.NewRequest("POST", e.url+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	req.AddCookie(e.cookie)
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestHome(t *testing.T) {
	e := newEnv(t)
	if code, body := e.get(t, "/", false); code != 200 || !strings.Contains(body, "<h1>Every Tool. Your Rules.</h1>") ||
		!strings.Contains(body, `href="/login">Sign in</a>`) || strings.Contains(body, "Google") {
		t.Errorf("signed out: %d", code)
	}
	code, body := e.get(t, "/", true)
	for _, want := range []string{"rahmad@example.com", e.url + "/mcp", "Fake", "Not connected", "Example MCP", "claude mcp add --transport http valetkey"} {
		if code != 200 || !strings.Contains(body, want) {
			t.Errorf("home missing %q (status %d)", want, code)
		}
	}
}

func TestConnectFlow(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	if code, _ := e.post(t, "/connect/fake", url.Values{"token": {"good"}}, ""); code != http.StatusForbidden {
		t.Errorf("no Origin: %d", code)
	}
	if code, _ := e.post(t, "/connect/fake", url.Values{"token": {"good"}}, "https://evil.example"); code != http.StatusForbidden {
		t.Errorf("foreign Origin: %d", code)
	}
	if code, body := e.post(t, "/connect/fake", url.Values{"token": {""}}, e.url); code != 400 || !strings.Contains(body, "Token is required.") {
		t.Errorf("missing field: %d", code)
	}
	if code, body := e.post(t, "/connect/fake", url.Values{"token": {"bad"}}, e.url); code != 400 || !strings.Contains(body, "Could not verify these credentials: rejected by fake") {
		t.Errorf("bad token: %d %s", code, body)
	}
	if _, err := e.creds.Load(ctx, e.user.ID, "fake"); !errors.Is(err, tools.ErrNotConnected) {
		t.Errorf("rejected creds were stored: %v", err)
	}
	if code, _ := e.post(t, "/connect/fake", url.Values{"token": {"good"}}, e.url); code != http.StatusSeeOther {
		t.Errorf("good token: %d", code)
	}
	if c, err := e.creds.Load(ctx, e.user.ID, "fake"); err != nil || c["token"] != "good" {
		t.Errorf("Load = %v, %v", c, err)
	}
	if _, body := e.get(t, "/", true); !strings.Contains(body, "Connected") || strings.Contains(body, "Not connected") {
		t.Error("home does not show Fake as connected")
	}
	if code, _ := e.post(t, "/connect/fake", url.Values{"action": {"disconnect"}}, e.url); code != http.StatusSeeOther {
		t.Errorf("disconnect: %d", code)
	}
	if _, err := e.creds.Load(ctx, e.user.ID, "fake"); !errors.Is(err, tools.ErrNotConnected) {
		t.Errorf("after disconnect: %v", err)
	}
}

func TestConnectPages(t *testing.T) {
	e := newEnv(t)
	if code, _ := e.get(t, "/connect/unknown", true); code != 404 {
		t.Errorf("unknown system: %d", code)
	}
	if code, _ := e.get(t, "/connect/fake", false); code != http.StatusFound {
		t.Errorf("signed out: %d", code)
	}
	code, body := e.get(t, "/connect/fake", true)
	if code != 200 || !strings.Contains(body, `type="password" name="token"`) {
		t.Errorf("form: %d", code)
	}
}

func TestTokens(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if code, _ := e.get(t, "/tokens", false); code != http.StatusFound {
		t.Errorf("signed out: %d", code)
	}
	if code, body := e.get(t, "/tokens", true); code != 200 || !strings.Contains(body, "No tokens yet. Create one below when a bot needs to reach valetkey.") || !strings.Contains(body, `value="jenkins_deploy"`) {
		t.Errorf("empty page: %d", code)
	}
	good := url.Values{"name": {"atlas"}, "tools": {"loki_query", "jenkins_deploy"}, "scope": {`{"fake":"x"}`}, "expiry": {"30"}}
	if code, _ := e.post(t, "/tokens", good, "https://evil.example"); code != http.StatusForbidden {
		t.Errorf("foreign Origin: %d", code)
	}
	for name, form := range map[string]url.Values{
		"unknown tool": {"name": {"x"}, "tools": {"rm_rf"}, "expiry": {"30"}},
		"bad scope":    {"name": {"x"}, "tools": {"loki_query"}, "scope": {`{"jenkin":"x"}`}, "expiry": {"30"}},
		"bad expiry":   {"name": {"x"}, "tools": {"loki_query"}, "expiry": {"365"}},
		"no tools":     {"name": {"x"}, "expiry": {"30"}},
		"negative":     {"name": {"x"}, "tools": {"loki_query"}, "expiry": {"30"}, "max_writes": {"-1"}},
		"not a number": {"name": {"x"}, "tools": {"loki_query"}, "expiry": {"30"}, "max_writes": {"abc"}},
		"too many":     {"name": {"x"}, "tools": {"loki_query"}, "expiry": {"30"}, "max_writes": {"1001"}},
	} {
		if code, body := e.post(t, "/tokens", form, e.url); code != 400 || !strings.Contains(body, `class="error" role="alert"`) {
			t.Errorf("%s: %d", name, code)
		}
	}
	if list, _ := e.as.Store.ListPersonalTokens(ctx, e.user.ID); len(list) != 0 {
		t.Fatalf("rejected forms created %d tokens", len(list))
	}

	code, body := e.post(t, "/tokens", good, e.url)
	m := regexp.MustCompile(`<pre class="key">(vk_[A-Z0-9]+)</pre>`).FindStringSubmatch(body)
	if code != 200 || m == nil || !strings.Contains(body, "Authorization: Bearer "+m[1]) {
		t.Fatalf("create: %d\n%s", code, body)
	}
	ti, err := e.as.Verify(ctx, m[1], nil)
	if r := tools.RestrictionOf(ti); err != nil || r == nil || !r.Allows("jenkins_deploy") || r.Scope["fake"].([]string)[0] != "x" {
		t.Fatalf("created token: %+v %v", r, err)
	}
	if r := tools.RestrictionOf(ti); r.MaxWritesPerHour != 20 || r.DryRun {
		t.Errorf("defaults: max %d dry %v", r.MaxWritesPerHour, r.DryRun)
	}
	capped := url.Values{"name": {"capped"}, "tools": {"jenkins_deploy"}, "expiry": {"30"}, "max_writes": {"5"}, "dry_run": {"on"}}
	_, cbody := e.post(t, "/tokens", capped, e.url)
	cm := regexp.MustCompile(`<pre class="key">(vk_[A-Z0-9]+)</pre>`).FindStringSubmatch(cbody)
	if cm == nil {
		t.Fatalf("capped create failed\n%s", cbody)
	}
	cti, err := e.as.Verify(ctx, cm[1], nil)
	if r := tools.RestrictionOf(cti); err != nil || r.MaxWritesPerHour != 5 || !r.DryRun {
		t.Errorf("capped token: %+v %v", r, err)
	}
	if _, body := e.get(t, "/tokens", true); !strings.Contains(body, "atlas") || strings.Contains(body, m[1]) {
		t.Error("list shows the token value or misses the name")
	}

	list, _ := e.as.Store.ListPersonalTokens(ctx, e.user.ID)
	list = slices.DeleteFunc(list, func(p store.PersonalToken) bool { return p.Name != "atlas" })
	if code, _ := e.post(t, "/tokens/"+list[0].ID+"/revoke", nil, "https://evil.example"); code != http.StatusForbidden {
		t.Errorf("revoke foreign Origin: %d", code)
	}
	if code, _ := e.post(t, "/tokens/"+list[0].ID+"/revoke", nil, e.url); code != http.StatusSeeOther {
		t.Errorf("revoke: %d", code)
	}
	if _, err := e.as.Verify(ctx, m[1], nil); err == nil {
		t.Error("revoked token still verifies")
	}
	if code, _ := e.post(t, "/tokens/00000000-0000-0000-0000-000000000000/revoke", nil, e.url); code != http.StatusNotFound {
		t.Errorf("revoke unknown: %d", code)
	}
}

func TestConnectPageShowsHelp(t *testing.T) {
	e := newEnv(t)
	code, body := e.get(t, "/connect/fake", true)
	if code != 200 || !strings.Contains(body, "Where to find these values") || !strings.Contains(body, "Open Fake &lt;settings&gt; and copy the token.") {
		t.Errorf("help missing or unescaped (status %d)", code)
	}
}

func TestActivity(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	other, _ := e.as.Store.UpsertUser(ctx, "bob@example.com")
	e.as.Store.RecordCall(ctx, store.ToolCall{UserID: e.user.ID, TokenName: "atlas", Tool: "jenkins_deploy", IsWrite: true, Outcome: "refused", Message: "refused: jenkins_deploy: job \"x\" is outside", Args: `{"jobURL":"<x>"}`})
	e.as.Store.RecordCall(ctx, store.ToolCall{UserID: e.user.ID, Tool: "loki_query", Outcome: "ok", Args: `{}`})
	e.as.Store.RecordCall(ctx, store.ToolCall{UserID: other.ID, Tool: "secret_tool", Outcome: "ok", Args: `{}`})

	if code, _ := e.get(t, "/activity", false); code != http.StatusFound {
		t.Errorf("signed out: %d", code)
	}
	code, body := e.get(t, "/activity", true)
	if code != 200 || !strings.Contains(body, "jenkins_deploy") || !strings.Contains(body, "loki_query") || strings.Contains(body, "secret_tool") {
		t.Errorf("own activity: %d", code)
	}
	if !strings.Contains(body, "&lt;x&gt;") {
		t.Error("arguments are not escaped")
	}
	if _, body := e.get(t, "/activity?outcome=refused", true); strings.Contains(body, "loki_query") {
		t.Error("outcome filter ignored")
	}
	if _, body := e.get(t, "/activity?user="+other.Email, true); strings.Contains(body, "secret_tool") {
		t.Error("a non-admin read another user's calls")
	}
	e.as.Store.RecordCall(ctx, store.ToolCall{UserID: other.ID, TokenName: "bobs-bot", Tool: "bob_only_tool", Outcome: "ok", Args: `{}`})
	if _, body := e.get(t, "/activity?token=bobs-bot", true); strings.Contains(body, "bob_only_tool") {
		t.Error("a non-admin read another user's calls by token name")
	}
	if _, body := e.get(t, "/activity?tool=nothing_here", true); !strings.Contains(body, "No calls match") {
		t.Error("filtered empty state missing")
	}
	e.web.AdminEmails = []string{"rahmad@example.com"}
	if _, body := e.get(t, "/activity", true); !strings.Contains(body, "secret_tool") || !strings.Contains(body, "bob@example.com") {
		t.Error("admin does not see everyone's calls")
	}
	if _, body := e.get(t, "/activity?user=BOB@example.com", true); !strings.Contains(body, "secret_tool") || strings.Contains(body, "loki_query") || !strings.Contains(body, "User email") {
		t.Error("admin email filter does not narrow to that user")
	}
}

func TestTokenRowShowsDryRunWithLimit(t *testing.T) {
	e := newEnv(t)
	if _, err := e.as.Store.CreatePersonalToken(context.Background(), store.PersonalToken{UserID: e.user.ID, Name: "dry", Tools: []string{"loki_query"}, Scope: []byte(`{}`), MaxWritesPerHour: 20, DryRun: true}, []byte("hd")); err != nil {
		t.Fatal(err)
	}
	if _, body := e.get(t, "/tokens", true); !strings.Contains(body, "dry run · 20 writes/hour") {
		t.Error("dry run row does not show the write limit")
	}
}

func TestEmptyActivity(t *testing.T) {
	e := newEnv(t)
	if _, body := e.get(t, "/activity", true); !strings.Contains(body, "No tool calls yet. When an agent uses one of your connections, the call shows up here.") {
		t.Error("empty state missing")
	}
}

func TestWriteToolBadgeIsNotAnError(t *testing.T) {
	e := newEnv(t)
	_, body := e.get(t, "/tokens", true)
	if !strings.Contains(body, `<span class="writes">changes things</span>`) || strings.Contains(body, `class="error"`) {
		t.Error("the write-tool badge should have its own class, and a clean page has no error")
	}
}

// Every localStorage access must sit inside a try block: it throws in private
// windows and when site data is blocked.
var storageInTry = regexp.MustCompile(`try\{[^}]*localStorage[^}]*\}catch`)

func TestEveryPageHasThemeToggle(t *testing.T) {
	e := newEnv(t)
	for _, p := range []struct {
		path     string
		signedIn bool
	}{{"/", false}, {"/", true}, {"/connect/fake", true}, {"/tokens", true}, {"/activity", true}, {"/upstreams", true}} {
		code, body := e.get(t, p.path, p.signedIn)
		if code != 200 || !strings.Contains(body, "data-theme-toggle") {
			t.Errorf("%s (signed in %v): no theme toggle (status %d)", p.path, p.signedIn, code)
		}
		if strings.Contains(body, "\u2014") {
			t.Errorf("%s (signed in %v): contains an em dash", p.path, p.signedIn)
		}
		if n := strings.Count(body, "localStorage"); n == 0 || len(storageInTry.FindAllString(body, -1)) != n {
			t.Errorf("%s (signed in %v): localStorage used outside try/catch", p.path, p.signedIn)
		}
	}
}

func TestHomeKeepsOneAmberFocus(t *testing.T) {
	e := newEnv(t)
	_, body := e.get(t, "/", true)
	if !strings.Contains(body, `<pre class="key">`+e.url+"/mcp</pre>") || regexp.MustCompile(`class="[^"]*\bprimary\b`).MatchString(body) {
		t.Error("home should highlight only the MCP address, not the Connect buttons")
	}
}

func TestRevokeLabelStaysShort(t *testing.T) {
	e := newEnv(t)
	long := strings.Repeat("x", 44)
	if _, err := e.as.Store.CreatePersonalToken(context.Background(), store.PersonalToken{UserID: e.user.ID, Name: long, Tools: []string{"loki_query"}, Scope: []byte(`{}`)}, []byte("h")); err != nil {
		t.Fatal(err)
	}
	if _, body := e.get(t, "/tokens", true); !strings.Contains(body, `aria-label="Revoke `+long+`">Revoke</button>`) {
		t.Error("revoke button should show a short label and name the token in aria-label")
	}
}

func TestTimesAreLabelledUTC(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("WIB", 7*3600))
	e.as.Store.RecordCall(ctx, store.ToolCall{UserID: e.user.ID, Tool: "loki_query", Outcome: "ok", Args: `{}`, At: at})
	if _, body := e.get(t, "/activity", true); !strings.Contains(body, "2026-01-01 20:04:05 UTC") {
		t.Error("activity time is not shown as UTC")
	}
	if _, err := e.as.Store.CreatePersonalToken(ctx, store.PersonalToken{UserID: e.user.ID, Name: "used", Tools: []string{"loki_query"}, Scope: []byte(`{}`), LastUsedAt: &at}, []byte("hu")); err != nil {
		t.Fatal(err)
	}
	if _, body := e.get(t, "/tokens", true); !strings.Contains(body, "last used 2026-01-01 20:04 UTC") || !strings.Contains(body, `title="Dates and times are UTC"`) {
		t.Error("token times are not labelled UTC")
	}
}

// proxiedInt stands in for one of a user's own MCP servers.
type proxiedInt struct{ name string }

func (p proxiedInt) System() string                            { return "upstream:" + p.name }
func (p proxiedInt) Title() string                             { return p.name }
func (proxiedInt) Fields() []tools.Field                       { return nil }
func (proxiedInt) Validate(context.Context, tools.Creds) error { return nil }
func (p proxiedInt) Tools() []tools.Tool {
	return []tools.Tool{{Name: p.name + "__echo", Description: "echo", Unscoped: true},
		{Name: p.name + "__write", Description: "write", Destructive: true, Unscoped: true}}
}

func TestTokenFormListsTheUsersOwnMCPTools(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	const sentence = "valetkey limits which of these tools a token may call, not what they touch."
	if _, body := e.get(t, "/tokens", true); strings.Contains(body, "From your MCP servers") {
		t.Error("the group shows for a user without MCP servers")
	}
	e.web.UserTools = func(_ context.Context, userID string) ([]tools.Integration, error) {
		if userID == e.user.ID {
			return []tools.Integration{proxiedInt{"github"}}, nil
		}
		return []tools.Integration{proxiedInt{"other"}}, nil
	}
	code, body := e.get(t, "/tokens", true)
	for _, want := range []string{"<legend>From your MCP servers</legend>", sentence, `value="github__echo"`, `value="loki_query"`,
		`<code>github__write</code> <span class="writes">changes things</span>`} {
		if code != 200 || !strings.Contains(body, want) {
			t.Errorf("tokens page misses %q (status %d)", want, code)
		}
	}
	if strings.Contains(body, "other__echo") {
		t.Error("another user's MCP tool is listed")
	}
	if i, j := strings.Index(body, `value="loki_query"`), strings.Index(body, `value="github__echo"`); i > j {
		t.Error("the user's MCP tools should follow the native tools")
	}

	code, body = e.post(t, "/tokens", url.Values{"name": {"bot"}, "tools": {"github__echo", "loki_query"}, "expiry": {"7"}}, e.url)
	m := regexp.MustCompile(`<pre class="key">(vk_[A-Z0-9]+)</pre>`).FindStringSubmatch(body)
	if code != 200 || m == nil {
		t.Fatalf("create with a proxied tool: %d", code)
	}
	if ti, err := e.as.Verify(ctx, m[1], nil); err != nil || !tools.RestrictionOf(ti).Allows("github__echo") {
		t.Errorf("created token: %v", err)
	}
	if code, body := e.post(t, "/tokens", url.Values{"name": {"x"}, "tools": {"other__echo"}, "expiry": {"7"}}, e.url); code != 400 || !strings.Contains(body, "Unknown tool other__echo.") {
		t.Errorf("another user's tool: %d", code)
	}
	if code, body := e.post(t, "/tokens", url.Values{"name": {"x"}, "tools": {"github__echo"}, "expiry": {"7"}, "max_writes": {"-1"}}, e.url); code != 400 || !strings.Contains(body, `value="github__echo" checked`) {
		t.Errorf("a rejected form should keep the proxied tool ticked: %d", code)
	}
}

func TestTokenFormFailsCleanlyWhenMCPLookupFails(t *testing.T) {
	e := newEnv(t)
	e.web.UserTools = func(context.Context, string) ([]tools.Integration, error) { return nil, errors.New("db down") }
	if code, _ := e.get(t, "/tokens", true); code != http.StatusInternalServerError {
		t.Errorf("status %d", code)
	}
}

func TestFontsAreServed(t *testing.T) {
	e := newEnv(t)
	resp, err := http.Get(e.url + "/fonts/figtree-latin-400-normal.woff2")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "font/woff2" {
		t.Errorf("status %d, type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}
