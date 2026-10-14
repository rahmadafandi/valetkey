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
	"strings"
	"testing"

	"github.com/rahmadafandi/valetkey/internal/auth"
	"github.com/rahmadafandi/valetkey/internal/creds"
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
	as := &auth.Server{Store: st, Signer: auth.NewSigner([]byte(strings.Repeat("k", 32))), PublicURL: pub,
		Integrations: []tools.Integration{fakeInt{}}}
	h := &Web{Auth: as, Creds: cr, Integrations: []tools.Integration{fakeInt{}},
		Catalog:   []CatalogEntry{{Name: "Example MCP", Description: "Inbox tools", Setup: "npx example-mcp"}},
		PublicURL: pub, Log: slog.New(slog.DiscardHandler)}
	mux := http.NewServeMux()
	h.Routes(mux)
	ts.Config.Handler = mux
	ts.Start()
	t.Cleanup(ts.Close)
	u, err := st.UpsertUser(context.Background(), "rahmad@example.com")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	as.SetSession(rec, u)
	return &env{url: pub, creds: cr, as: as, user: u, cookie: rec.Result().Cookies()[0]}
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
	if code, body := e.get(t, "/", false); code != 200 || !strings.Contains(body, "Sign in with Google") {
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
	if code, body := e.get(t, "/tokens", true); code != 200 || !strings.Contains(body, "No tokens yet.") || !strings.Contains(body, `value="jenkins_deploy"`) {
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
	} {
		if code, body := e.post(t, "/tokens", form, e.url); code != 400 || !strings.Contains(body, `class="error"`) {
			t.Errorf("%s: %d", name, code)
		}
	}
	if list, _ := e.as.Store.ListPersonalTokens(ctx, e.user.ID); len(list) != 0 {
		t.Fatalf("rejected forms created %d tokens", len(list))
	}

	code, body := e.post(t, "/tokens", good, e.url)
	m := regexp.MustCompile(`<pre>(vk_[A-Z0-9]+)</pre>`).FindStringSubmatch(body)
	if code != 200 || m == nil || !strings.Contains(body, "Authorization: Bearer "+m[1]) {
		t.Fatalf("create: %d\n%s", code, body)
	}
	ti, err := e.as.Verify(ctx, m[1], nil)
	if r := tools.RestrictionOf(ti); err != nil || r == nil || !r.Allows("jenkins_deploy") || r.Scope["fake"].([]string)[0] != "x" {
		t.Fatalf("created token: %+v %v", r, err)
	}
	if _, body := e.get(t, "/tokens", true); !strings.Contains(body, "atlas") || strings.Contains(body, m[1]) {
		t.Error("list shows the token value or misses the name")
	}

	list, _ := e.as.Store.ListPersonalTokens(ctx, e.user.ID)
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
