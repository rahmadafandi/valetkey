package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/rahmadafandi/valetkey/internal/store"
	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/upstream"
	"github.com/rahmadafandi/valetkey/internal/version"
)

type asOpts struct {
	NoRegistration bool
	OIDCOnly       bool   // metadata only at /.well-known/openid-configuration
	TokenURL       string // overrides the advertised token_endpoint
	RegisterURL    string // overrides the advertised registration_endpoint
	AuthorizeURL   string // overrides the advertised authorization_endpoint
}

// fakeAS is an authorization server issuing tokens the fake MCP server accepts.
// Refresh tokens rotate: each one works once.
type fakeAS struct {
	URL  string
	opts asOpts

	mu           sync.Mutex
	n            int
	registration map[string]any
	regUA        string
	challenge    string // code_challenge of the last authorization
	authQuery    url.Values
	codes        map[string]bool
	access       map[string]bool
	refresh      map[string]bool
	refreshes    int
	rejectAll    bool // refresh requests fail with invalid_grant
	tokenForms   []url.Values
}

func newAS(t *testing.T, opts asOpts) *fakeAS {
	t.Helper()
	as := &fakeAS{opts: opts, codes: map[string]bool{}, access: map[string]bool{}, refresh: map[string]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(as.serve))
	t.Cleanup(srv.Close)
	as.URL = srv.URL
	return as
}

func (as *fakeAS) serve(w http.ResponseWriter, r *http.Request) {
	as.mu.Lock()
	defer as.mu.Unlock()
	metaPath := "/.well-known/oauth-authorization-server"
	if as.opts.OIDCOnly {
		metaPath = "/.well-known/openid-configuration"
	}
	switch r.URL.Path {
	case metaPath:
		meta := map[string]any{
			"issuer":                           as.URL,
			"authorization_endpoint":           or(as.opts.AuthorizeURL, as.URL+"/authorize"),
			"token_endpoint":                   or(as.opts.TokenURL, as.URL+"/token"),
			"code_challenge_methods_supported": []string{"S256"},
		}
		if !as.opts.NoRegistration {
			meta["registration_endpoint"] = or(as.opts.RegisterURL, as.URL+"/register")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	case "/register":
		as.regUA = r.UserAgent()
		json.NewDecoder(r.Body).Decode(&as.registration)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"client_id":"dyn-client","redirect_uris":["x"]}`)
	case "/token":
		r.ParseForm()
		as.tokenForms = append(as.tokenForms, r.PostForm)
		switch r.PostForm.Get("grant_type") {
		case "authorization_code":
			code, v := r.PostForm.Get("code"), r.PostForm.Get("code_verifier")
			sum := sha256.Sum256([]byte(v))
			if !as.codes[code] || base64.RawURLEncoding.EncodeToString(sum[:]) != as.challenge {
				tokenError(w)
				return
			}
			delete(as.codes, code)
		case "refresh_token":
			rt := r.PostForm.Get("refresh_token")
			if as.rejectAll || !as.refresh[rt] {
				tokenError(w)
				return
			}
			delete(as.refresh, rt)
			as.refreshes++
		default:
			tokenError(w)
			return
		}
		as.n++
		acc, ref := fmt.Sprintf("acc-%d", as.n), fmt.Sprintf("ref-%d", as.n)
		as.access[acc], as.refresh[ref] = true, true
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q,"refresh_token":%q,"token_type":"Bearer","expires_in":3600}`, acc, ref)
	default:
		http.NotFound(w, r)
	}
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func tokenError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprint(w, `{"error":"invalid_grant"}`)
}

// authorize plays the browser and the user: it approves the request and returns the code.
func (as *fakeAS) authorize(t *testing.T, authURL string) string {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	as.mu.Lock()
	defer as.mu.Unlock()
	as.authQuery, as.challenge = q, q.Get("code_challenge")
	as.n++
	code := fmt.Sprintf("code-%d", as.n)
	as.codes[code] = true
	return code
}

// locked runs f holding the server's lock, so tests read its state without racing it.
func (as *fakeAS) locked(f func()) {
	as.mu.Lock()
	defer as.mu.Unlock()
	f()
}

func (as *fakeAS) refreshCount() (n int) {
	as.locked(func() { n = as.refreshes })
	return n
}

func (as *fakeAS) valid(tok string) bool {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.access[tok]
}

func (as *fakeAS) revoke(tok string) {
	as.mu.Lock()
	defer as.mu.Unlock()
	delete(as.access, tok)
}

// privateLookup resolves *.internal to a private address, as a hostile DNS answer would.
func privateLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if strings.HasSuffix(host, ".internal") {
		return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

type oauthEnv struct {
	p      *Proxy
	as     *fakeAS
	f      *fake
	userID string
	u      store.Upstream
}

// newOAuthEnv sets up an OAuth upstream with one approved tool, "echo", not yet signed in.
func newOAuthEnv(t *testing.T, ao asOpts, challenge bool) *oauthEnv {
	t.Helper()
	as := newAS(t, ao)
	f := newFake(t, fakeOpts{Bearer: as.valid, AuthServer: as.URL, Challenge: challenge, Tools: []fakeTool{{Name: "echo"}}})
	f.Guard.Lookup = privateLookup
	p := newProxy(t, f)
	user, err := p.Store.UpsertUser(ctx, "a@example.com")
	if err != nil {
		t.Fatal(err)
	}
	u, err := p.Store.CreateUpstream(ctx, store.Upstream{UserID: user.ID, Name: "notes", URL: f.URL, Auth: "oauth"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Store.ApproveTools(ctx, user.ID, u.ID, []store.UpstreamTool{{Name: "echo", InputSchema: `{"type":"object"}`}}); err != nil {
		t.Fatal(err)
	}
	return &oauthEnv{p: p, as: as, f: f, userID: user.ID, u: u}
}

func (e *oauthEnv) login(t *testing.T) {
	t.Helper()
	authURL, err := e.p.StartOAuth(ctx, e.userID, e.u, "", "", "st")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.p.FinishOAuth(ctx, e.userID, e.u, e.as.authorize(t, authURL)); err != nil {
		t.Fatal(err)
	}
}

func (e *oauthEnv) creds(t *testing.T) tools.Creds {
	t.Helper()
	c, err := e.p.Creds.Load(ctx, e.userID, CredsSystem(e.u.ID))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *oauthEnv) save(t *testing.T, c tools.Creds) {
	t.Helper()
	if err := e.p.Creds.Save(ctx, e.userID, CredsSystem(e.u.ID), c); err != nil {
		t.Fatal(err)
	}
}

func (e *oauthEnv) call(t *testing.T) (string, error) {
	t.Helper()
	ints, err := e.p.Integrations(ctx, e.userID)
	if err != nil {
		t.Fatal(err)
	}
	return call(t, e.p, e.userID, ints, "notes__echo", `{}`)
}

func TestOAuthDiscovery(t *testing.T) {
	for _, c := range []struct {
		name      string
		challenge bool
		ao        asOpts
	}{
		{"WWW-Authenticate header", true, asOpts{}},
		{"well-known fallback", false, asOpts{}},
		{"OpenID configuration", false, asOpts{OIDCOnly: true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newOAuthEnv(t, c.ao, c.challenge)
			authURL, err := e.p.StartOAuth(ctx, e.userID, e.u, "", "", "st")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(authURL, e.as.URL+"/authorize?") {
				t.Fatalf("auth URL %s", authURL)
			}
		})
	}
}

func TestOAuthRegistration(t *testing.T) {
	e := newOAuthEnv(t, asOpts{}, true)
	authURL, err := e.p.StartOAuth(ctx, e.userID, e.u, "", "", "st")
	if err != nil {
		t.Fatal(err)
	}
	var reg map[string]any
	var ua string
	e.as.locked(func() { reg, ua = e.as.registration, e.as.regUA })
	redirect := "https://valet.test/upstreams/" + e.u.ID + "/callback"
	if reg["client_name"] != "valetkey" || reg["token_endpoint_auth_method"] != "none" || fmt.Sprint(reg["redirect_uris"]) != "["+redirect+"]" {
		t.Fatalf("registration: %v", reg)
	}
	if ua != version.UserAgent() {
		t.Fatalf("registration User-Agent %q", ua)
	}
	q, _ := url.Parse(authURL)
	if q.Query().Get("client_id") != "dyn-client" || q.Query().Get("redirect_uri") != redirect {
		t.Fatalf("auth URL %s", authURL)
	}
}

func TestOAuthNeedsClient(t *testing.T) {
	e := newOAuthEnv(t, asOpts{NoRegistration: true}, true)
	if _, err := e.p.StartOAuth(ctx, e.userID, e.u, "", "", "st"); !errors.Is(err, ErrNeedClient) {
		t.Fatalf("no client: %v", err)
	}
	authURL, err := e.p.StartOAuth(ctx, e.userID, e.u, "my-client", "my-secret", "st")
	if err != nil {
		t.Fatal(err)
	}
	if q, _ := url.Parse(authURL); q.Query().Get("client_id") != "my-client" {
		t.Fatalf("auth URL %s", authURL)
	}
	if err := e.p.FinishOAuth(ctx, e.userID, e.u, e.as.authorize(t, authURL)); err != nil {
		t.Fatal(err)
	}
	if c := e.creds(t); c["client_id"] != "my-client" || c["client_secret"] != "my-secret" {
		t.Fatalf("stored client: %v", c)
	}
}

func TestOAuthAuthorizationURL(t *testing.T) {
	e := newOAuthEnv(t, asOpts{NoRegistration: true}, true)
	authURL, err := e.p.StartOAuth(ctx, e.userID, e.u, "my-client", "my-secret", "signed.state")
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.Parse(authURL)
	v := q.Query()
	if v.Get("code_challenge_method") != "S256" || v.Get("code_challenge") == "" || v.Get("resource") != e.f.URL || v.Get("state") != "signed.state" || v.Get("response_type") != "code" {
		t.Fatalf("auth URL %s", authURL)
	}
	c := e.creds(t)
	if c["pending"] != "1" || c["verifier"] == "" || c["token_endpoint"] != e.as.URL+"/token" || c["resource"] != e.f.URL {
		t.Fatalf("pending credential: %v", c)
	}
	for _, secret := range []string{c["verifier"], "my-secret"} {
		if strings.Contains(authURL, secret) || strings.Contains(authURL, url.QueryEscape(secret)) {
			t.Fatalf("auth URL carries %q: %s", secret, authURL)
		}
	}
	// A sign-in in progress is not a login.
	if _, err := e.call(t); !errors.Is(err, tools.ErrNotConnected) {
		t.Fatalf("call with a pending credential: %v", err)
	}
}

func TestOAuthFinishAndCall(t *testing.T) {
	e := newOAuthEnv(t, asOpts{}, true)
	e.login(t)
	c := e.creds(t)
	if c["pending"] != "" || c["verifier"] != "" || c["access_token"] != "acc-2" || c["refresh_token"] != "ref-2" || c["client_id"] != "dyn-client" || c["resource"] != e.f.URL {
		t.Fatalf("stored: %v", c)
	}
	if exp, err := time.Parse(time.RFC3339, c["expiry"]); err != nil || time.Until(exp) < 50*time.Minute {
		t.Fatalf("expiry %q %v", c["expiry"], err)
	}
	var form url.Values
	e.as.locked(func() { form = e.as.tokenForms[0] })
	if form.Get("resource") != e.f.URL || form.Get("redirect_uri") == "" {
		t.Fatalf("token request: %v", form)
	}
	if out, err := e.call(t); err != nil || out != "echo {}" {
		t.Fatalf("call: %q %v", out, err)
	}
	if _, auth, _ := e.f.seen(); auth != "Bearer acc-2" {
		t.Fatalf("upstream saw %q", auth)
	}
	if err := e.p.FinishOAuth(ctx, e.userID, e.u, "code-again"); err == nil {
		t.Fatal("finished a sign-in that was not started")
	}
}

func TestOAuthRefresh(t *testing.T) {
	e := newOAuthEnv(t, asOpts{}, true)
	e.login(t)

	// Expired: refreshed before the call.
	c := e.creds(t)
	c["expiry"] = time.Now().Add(10 * time.Second).Format(time.RFC3339)
	e.save(t, c)
	if out, err := e.call(t); err != nil || out != "echo {}" {
		t.Fatalf("expired: %q %v", out, err)
	}
	if c := e.creds(t); e.as.refreshCount() != 1 || c["access_token"] != "acc-3" || c["refresh_token"] != "ref-3" {
		t.Fatalf("after refresh: %d %v", e.as.refreshCount(), c)
	}

	// Revoked but not expired: the 401 triggers one refresh and a retry.
	e.as.revoke("acc-3")
	if out, err := e.call(t); err != nil || out != "echo {}" {
		t.Fatalf("revoked: %q %v", out, err)
	}
	if c := e.creds(t); e.as.refreshCount() != 2 || c["access_token"] != "acc-4" {
		t.Fatalf("after 401: %d %v", e.as.refreshCount(), c)
	}

	// The authorization server refuses: the user is sent back to /upstreams.
	e.as.locked(func() { e.as.rejectAll = true })
	e.as.revoke("acc-4")
	if _, err := e.call(t); !errors.Is(err, upstream.ErrUnauthorized) {
		t.Fatalf("rejected refresh: %v", err)
	}
	verify := func(context.Context, string, *http.Request) (*mcpauth.TokenInfo, error) {
		return &mcpauth.TokenInfo{UserID: e.userID, Expiration: time.Now().Add(time.Hour)}, nil
	}
	srv := httptest.NewServer(tools.HTTPHandler(nil, e.p.Integrations, e.p.Creds.Load, e.p.PublicURL, slog.New(slog.DiscardHandler), nil, verify, "https://valet.test/meta"))
	defer srv.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, nil).Connect(ctx,
		&mcp.StreamableClientTransport{Endpoint: srv.URL, HTTPClient: &http.Client{Transport: bearerRT{}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "notes__echo", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if text := res.Content[0].(*mcp.TextContent).Text; !res.IsError || !strings.HasSuffix(text, "Reconnect at https://valet.test/upstreams") {
		t.Fatalf("handler said %q", text)
	}
}

type bearerRT struct{}

func (bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer agent")
	return http.DefaultTransport.RoundTrip(r)
}

// Two calls see the same expired token: one refresh happens and the rotated
// refresh token is the one kept.
func TestOAuthRefreshRace(t *testing.T) {
	e := newOAuthEnv(t, asOpts{}, true)
	e.login(t)
	c := e.creds(t)
	c["expiry"] = time.Now().Add(-time.Minute).Format(time.RFC3339)
	e.save(t, c)
	ints, err := e.p.Integrations(ctx, e.userID)
	if err != nil {
		t.Fatal(err)
	}
	_, tl := findTool(t, ints, "notes__echo")
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if _, err := tl.Run(ctx, c, json.RawMessage(`{}`)); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if n := e.as.refreshCount(); n != 1 {
		t.Fatalf("%d refreshes", n)
	}
	var live bool
	c = e.creds(t)
	e.as.locked(func() { live = e.as.refresh[c["refresh_token"]] })
	if !live {
		t.Fatalf("stored refresh token %q is not the live one", c["refresh_token"])
	}
}

func TestOAuthSSRF(t *testing.T) {
	t.Run("authorization server on a private address", func(t *testing.T) {
		f := newFake(t, fakeOpts{Bearer: func(string) bool { return false }, AuthServer: "https://10.0.0.1", Challenge: true})
		p := newProxy(t, f)
		u := store.Upstream{ID: "u1", Name: "evil", URL: f.URL, Auth: "oauth"}
		if _, err := p.StartOAuth(ctx, "user", u, "", "", "st"); err == nil || !strings.Contains(err.Error(), "netguard") {
			t.Fatalf("StartOAuth: %v", err)
		}
	})
	t.Run("registration endpoint on a private address", func(t *testing.T) {
		e := newOAuthEnv(t, asOpts{RegisterURL: "https://reg.internal/register"}, true)
		if _, err := e.p.StartOAuth(ctx, e.userID, e.u, "", "", "st"); err == nil || !strings.Contains(err.Error(), "netguard") {
			t.Fatalf("StartOAuth: %v", err)
		}
	})
	t.Run("token endpoint on a private address", func(t *testing.T) {
		e := newOAuthEnv(t, asOpts{TokenURL: "https://token.internal/token"}, true)
		authURL, err := e.p.StartOAuth(ctx, e.userID, e.u, "", "", "st")
		if err != nil {
			t.Fatal(err)
		}
		if err := e.p.FinishOAuth(ctx, e.userID, e.u, e.as.authorize(t, authURL)); err == nil || !strings.Contains(err.Error(), "netguard") {
			t.Fatalf("FinishOAuth: %v", err)
		}
	})
	t.Run("authorization endpoint is never fetched", func(t *testing.T) {
		e := newOAuthEnv(t, asOpts{AuthorizeURL: "https://login.internal/authorize"}, true)
		if _, err := e.p.StartOAuth(ctx, e.userID, e.u, "", "", "st"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("authorization endpoint over http", func(t *testing.T) {
		e := newOAuthEnv(t, asOpts{AuthorizeURL: "http://login.example/authorize"}, true)
		if _, err := e.p.StartOAuth(ctx, e.userID, e.u, "", "", "st"); err == nil {
			t.Fatal("accepted an http authorization endpoint")
		}
	})
}
