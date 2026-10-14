package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/rahmadafandi/valetkey/internal/integrations/bitbucket"
	"github.com/rahmadafandi/valetkey/internal/integrations/jenkins"
	"github.com/rahmadafandi/valetkey/internal/store"
	"github.com/rahmadafandi/valetkey/internal/tools"
)

const verifier = "verifier-0123456789-0123456789-0123456789-0123"

func challenge(v string) string {
	s := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

type env struct {
	url string
	as  *Server
}

func newEnv(t *testing.T, claims map[string]any) *env {
	idp := fakeIdP(t, func(string) map[string]any { return claims }, "")
	ts := httptest.NewUnstartedServer(nil)
	pub := "http://" + ts.Listener.Addr().String()
	j, err := jenkins.New("https://jenkins.example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	as := &Server{
		Store:  store.OpenTest(t),
		Signer: NewSigner([]byte(strings.Repeat("k", 32))),
		IdP: &OIDC{Issuer: googleIssuer, AllowedDomains: []string{"example.com"},
			Config: &oauth2.Config{ClientID: "gid", ClientSecret: "gs", RedirectURL: pub + "/oauth/oidc/callback",
				Endpoint: oauth2.Endpoint{AuthURL: idp.URL + "/auth", TokenURL: idp.URL + "/token"}, Scopes: []string{"openid", "email"}}},
		PublicURL: pub,
		AccessTTL: time.Hour, RefreshTTL: 720 * time.Hour, Log: slog.New(slog.DiscardHandler),
		Integrations: []tools.Integration{j, bitbucket.New("https://bitbucket.example.com", false)},
	}
	mux := http.NewServeMux()
	as.Routes(mux)
	ts.Config.Handler = mux
	ts.Start()
	t.Cleanup(ts.Close)
	return &env{url: pub, as: as}
}

func browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (e *env) register(t *testing.T, redirect string) string {
	t.Helper()
	resp, err := http.Post(e.url+"/oauth/register", "application/json",
		strings.NewReader(`{"client_name":"Claude","redirect_uris":["`+redirect+`"]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusCreated || out["token_endpoint_auth_method"] != "none" {
		t.Fatalf("register: %d %v", resp.StatusCode, out)
	}
	return out["client_id"].(string)
}

// authorize walks /oauth/authorize → (identity provider) → callback and returns the final redirect.
func (e *env) authorize(t *testing.T, hc *http.Client, clientID, redirect string) *http.Response {
	t.Helper()
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}, "state": {"xyz"}}
	resp, err := hc.Get(e.url + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		return resp
	}
	loc, _ := resp.Location()
	resp, err = hc.Get(e.url + "/oauth/oidc/callback?" + url.Values{"code": {"gcode"}, "state": {loc.Query().Get("state")}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return resp
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return e.consent(t, hc, consentValue(t, body), "approve", e.url)
}

var consentRe = regexp.MustCompile(`name="consent" value="([^"]+)"`)

func consentValue(t *testing.T, page []byte) string {
	t.Helper()
	m := consentRe.FindSubmatch(page)
	if m == nil {
		t.Fatalf("no consent value in page: %s", page)
	}
	return string(m[1])
}

func (e *env) consent(t *testing.T, hc *http.Client, consent, action, origin string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", e.url+"/oauth/consent", strings.NewReader(url.Values{"consent": {consent}, "action": {action}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

// consentPage walks authorize -> IdP callback and returns the consent page body.
func (e *env) consentPage(t *testing.T, hc *http.Client, clientID, redirect string) []byte {
	t.Helper()
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}, "state": {"xyz"}}
	resp, err := hc.Get(e.url + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := resp.Location()
	resp, err = hc.Get(e.url + "/oauth/oidc/callback?" + url.Values{"code": {"gcode"}, "state": {loc.Query().Get("state")}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback status = %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	return b
}

func (e *env) token(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(e.url+"/oauth/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestMetadata(t *testing.T) {
	e := newEnv(t, claims("a@example.com"))
	var as map[string]any
	resp, _ := http.Get(e.url + "/.well-known/oauth-authorization-server")
	json.NewDecoder(resp.Body).Decode(&as)
	resp.Body.Close()
	if as["issuer"] != e.url || as["token_endpoint"] != e.url+"/oauth/token" || as["registration_endpoint"] != e.url+"/oauth/register" {
		t.Errorf("AS metadata = %v", as)
	}
	var prm map[string]any
	resp, _ = http.Get(e.url + "/.well-known/oauth-protected-resource/mcp")
	json.NewDecoder(resp.Body).Decode(&prm)
	resp.Body.Close()
	if prm["resource"] != e.url+"/mcp" {
		t.Errorf("PRM = %v", prm)
	}
}

func TestFullFlow(t *testing.T) {
	e := newEnv(t, claims("Rahmad@Example.com"))
	const redirect = "http://127.0.0.1:33418/callback"
	id := e.register(t, redirect)
	hc := browser()
	resp := e.authorize(t, hc, id, redirect)
	loc, _ := resp.Location()
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc.String(), redirect) || loc.Query().Get("state") != "xyz" {
		t.Fatalf("callback redirect: %d %v", resp.StatusCode, loc)
	}
	code := loc.Query().Get("code")

	status, tok := e.token(t, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {id},
		"redirect_uri": {redirect}, "code_verifier": {verifier}})
	if status != 200 || tok["token_type"] != "Bearer" || tok["expires_in"] != float64(3600) {
		t.Fatalf("token: %d %v", status, tok)
	}
	ti, err := e.as.Verify(context.Background(), tok["access_token"].(string), nil)
	if err != nil || ti.Extra["email"] != "rahmad@example.com" || ti.UserID == "" {
		t.Fatalf("Verify = %+v, %v", ti, err)
	}

	// The code is single-use.
	if status, out := e.token(t, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {id},
		"redirect_uri": {redirect}, "code_verifier": {verifier}}); status != 400 || out["error"] != "invalid_grant" {
		t.Errorf("code reuse: %d %v", status, out)
	}

	// Refresh rotates; the old refresh token is dead afterwards.
	oldRefresh := tok["refresh_token"].(string)
	status, tok2 := e.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {oldRefresh}, "client_id": {id}})
	if status != 200 || tok2["refresh_token"] == oldRefresh {
		t.Fatalf("refresh: %d %v", status, tok2)
	}
	if status, out := e.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {oldRefresh}, "client_id": {id}}); status != 400 || out["error"] != "invalid_grant" {
		t.Errorf("refresh reuse: %d %v", status, out)
	}
	if _, err := e.as.Verify(context.Background(), "not-a-token", nil); err == nil {
		t.Error("unknown token verified")
	}

	// Finishing MCP sign-in also signs the browser in to the web UI.
	req := &http.Request{Header: http.Header{}}
	for _, c := range hc.Jar.Cookies(mustURL(e.url)) {
		req.AddCookie(c)
	}
	if u, ok := e.as.WebUser(req); !ok || u.Email != "rahmad@example.com" {
		t.Errorf("WebUser after MCP sign-in = %+v %v", u, ok)
	}
}

func mustURL(s string) *url.URL { u, _ := url.Parse(s); return u }

func TestWrongVerifier(t *testing.T) {
	e := newEnv(t, claims("a@example.com"))
	const redirect = "https://claude.ai/api/mcp/auth_callback"
	id := e.register(t, redirect)
	resp := e.authorize(t, browser(), id, redirect)
	loc, _ := resp.Location()
	if status, out := e.token(t, url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "client_id": {id},
		"redirect_uri": {redirect}, "code_verifier": {"wrong"}}); status != 400 || out["error"] != "invalid_grant" {
		t.Errorf("wrong verifier: %d %v", status, out)
	}
}

func TestUnregisteredRedirectNotFollowed(t *testing.T) {
	e := newEnv(t, claims("a@example.com"))
	id := e.register(t, "https://claude.ai/cb")
	if resp := e.authorize(t, browser(), id, "https://evil.example/cb"); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestDomainRejected(t *testing.T) {
	e := newEnv(t, claims("someone@gmail.com"))
	id := e.register(t, "https://claude.ai/cb")
	if resp := e.authorize(t, browser(), id, "https://claude.ai/cb"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestCallbackNeedsNonceCookie(t *testing.T) {
	e := newEnv(t, claims("a@example.com"))
	id := e.register(t, "https://claude.ai/cb")
	q := url.Values{"response_type": {"code"}, "client_id": {id}, "redirect_uri": {"https://claude.ai/cb"},
		"code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}}
	resp, _ := browser().Get(e.url + "/oauth/authorize?" + q.Encode())
	loc, _ := resp.Location()
	// A different browser (no nonce cookie) presents the state.
	resp, _ = browser().Get(e.url + "/oauth/oidc/callback?" + url.Values{"code": {"g"}, "state": {loc.Query().Get("state")}}.Encode())
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestRegisterRedirectRules(t *testing.T) {
	e := newEnv(t, claims("a@example.com"))
	for uri, ok := range map[string]bool{
		"https://claude.ai/api/mcp/auth_callback": true,
		"http://localhost:5555/cb":                true,
		"http://127.0.0.1:5555/cb":                true,
		"cursor://anysphere.cursor-mcp/oauth":     true,
		"http://evil.example/cb":                  false,
		"javascript:alert(1)":                     false,
		"https://claude.ai/cb#frag":               false,
		"/relative":                               false,
	} {
		resp, _ := http.Post(e.url+"/oauth/register", "application/json", strings.NewReader(`{"redirect_uris":["`+uri+`"]}`))
		resp.Body.Close()
		if got := resp.StatusCode == http.StatusCreated; got != ok {
			t.Errorf("%s: created=%v want %v", uri, got, ok)
		}
	}
}

func TestWebLogin(t *testing.T) {
	e := newEnv(t, claims("a@example.com"))
	hc := browser()
	resp, _ := hc.Get(e.url + "/login")
	loc, _ := resp.Location()
	resp, _ = hc.Get(e.url + "/oauth/oidc/callback?" + url.Values{"code": {"g"}, "state": {loc.Query().Get("state")}}.Encode())
	if l, _ := resp.Location(); resp.StatusCode != http.StatusFound || l.Path != "/" {
		t.Fatalf("callback: %d %v", resp.StatusCode, l)
	}
	req := &http.Request{Header: http.Header{}}
	for _, c := range hc.Jar.Cookies(mustURL(e.url)) {
		req.AddCookie(c)
	}
	if u, ok := e.as.WebUser(req); !ok || u.Email != "a@example.com" {
		t.Errorf("WebUser = %+v %v", u, ok)
	}
}

func TestConsentDeny(t *testing.T) {
	e := newEnv(t, claims("a@example.com"))
	const redirect = "https://claude.ai/cb"
	id := e.register(t, redirect)
	hc := browser()
	resp := e.consent(t, hc, consentValue(t, e.consentPage(t, hc, id, redirect)), "deny", e.url)
	loc, _ := resp.Location()
	if resp.StatusCode != http.StatusFound || loc.Query().Get("error") != "access_denied" || loc.Query().Get("code") != "" || loc.Query().Get("state") != "xyz" {
		t.Errorf("deny: %d %v", resp.StatusCode, loc)
	}
}

func TestConsentNeedsOrigin(t *testing.T) {
	e := newEnv(t, claims("a@example.com"))
	const redirect = "https://claude.ai/cb"
	id := e.register(t, redirect)
	hc := browser()
	c := consentValue(t, e.consentPage(t, hc, id, redirect))
	for _, origin := range []string{"", "https://evil.example"} {
		if resp := e.consent(t, hc, c, "approve", origin); resp.StatusCode != http.StatusForbidden {
			t.Errorf("origin %q: status = %d", origin, resp.StatusCode)
		}
	}
}

func TestConsentReplayFromOtherBrowser(t *testing.T) {
	e := newEnv(t, claims("a@example.com"))
	const redirect = "https://claude.ai/cb"
	id := e.register(t, redirect)
	c := consentValue(t, e.consentPage(t, browser(), id, redirect))
	// Another browser has no session at all.
	if resp := e.consent(t, browser(), c, "approve", e.url); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("no session: status = %d", resp.StatusCode)
	}
	// Another browser signed in as a different user.
	other := browser()
	other.Jar.SetCookies(mustURL(e.url), nil)
	u, _ := e.as.Store.UpsertUser(context.Background(), "b@example.com")
	rec := httptest.NewRecorder()
	e.as.SetSession(rec, u)
	other.Jar.SetCookies(mustURL(e.url), rec.Result().Cookies())
	if resp := e.consent(t, other, c, "approve", e.url); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("other user: status = %d", resp.StatusCode)
	}
}

func TestConsentPageEscapesClientName(t *testing.T) {
	e := newEnv(t, claims("a@example.com"))
	const redirect = "https://claude.ai/cb"
	resp, err := http.Post(e.url+"/oauth/register", "application/json",
		strings.NewReader(`{"client_name":"<script>alert(1)</script>","redirect_uris":["`+redirect+`"]}`))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	page := string(e.consentPage(t, browser(), out["client_id"].(string), redirect))
	if strings.Contains(page, "<script>alert(1)") || !strings.Contains(page, "&lt;script&gt;") || !strings.Contains(page, "https://claude.ai") {
		t.Errorf("page = %s", page)
	}
}

func TestConsentPageHasThemeToggle(t *testing.T) {
	e := newEnv(t, claims("a@example.com"))
	const redirect = "https://claude.ai/cb"
	page := string(e.consentPage(t, browser(), e.register(t, redirect), redirect))
	for _, want := range []string{"data-theme-toggle", `value="approve">Approve</button>`, `value="deny">Deny</button>`} {
		if !strings.Contains(page, want) {
			t.Errorf("consent page misses %q", want)
		}
	}
	if strings.Contains(page, "\u2014") {
		t.Error("consent page contains an em dash")
	}
}

func TestRefreshKeepsOriginalExpiry(t *testing.T) {
	e := newEnv(t, claims("a@example.com"))
	const redirect = "https://claude.ai/cb"
	id := e.register(t, redirect)
	loc, _ := e.authorize(t, browser(), id, redirect).Location()
	_, tok := e.token(t, url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "client_id": {id},
		"redirect_uri": {redirect}, "code_verifier": {verifier}})
	ctx := context.Background()
	orig, _, err := e.as.Store.LookupToken(ctx, hash(tok["refresh_token"].(string)), "refresh")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	_, tok2 := e.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "client_id": {id}})
	next, _, err := e.as.Store.LookupToken(ctx, hash(tok2["refresh_token"].(string)), "refresh")
	if err != nil {
		t.Fatal(err)
	}
	if !next.ExpiresAt.Equal(orig.ExpiresAt) {
		t.Errorf("rotated expiry %v != original %v", next.ExpiresAt, orig.ExpiresAt)
	}
}

func claims(email string) map[string]any {
	return map[string]any{"iss": googleIssuer, "aud": "gid", "email": email, "email_verified": true, "hd": email[strings.LastIndex(email, "@")+1:]}
}
