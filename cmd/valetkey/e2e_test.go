package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"

	"github.com/rahmadafandi/valetkey/internal/auth"
	"github.com/rahmadafandi/valetkey/internal/config"
	"github.com/rahmadafandi/valetkey/internal/store"
)

type bearer string

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+string(b))
	return http.DefaultTransport.RoundTrip(r)
}

func TestEndToEnd(t *testing.T) {
	ctx := context.Background()
	st := store.OpenTest(t)

	jenkins := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "alice" || p != "tok" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/me/api/json":
			w.Write([]byte(`{"id":"alice"}`))
		case "/job/app/api/json":
			w.Write([]byte(`{"builds":[{"number":7,"result":"SUCCESS","timestamp":1760396400000,"changeSet":{"items":[]}}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer jenkins.Close()

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "catalog.json"), []byte(`[{"name":"valetkey","description":"this server"}]`), 0o600)

	ts := httptest.NewUnstartedServer(nil)
	pub := "http://" + ts.Listener.Addr().String()
	cfg := config.Config{
		PublicURL: pub, GoogleClientID: "gid", AllowedDomains: []string{"example.com"},
		VaultKey: bytes.Repeat([]byte{1}, 32), SessionKey: []byte(strings.Repeat("s", 32)),
		AccessTTL: time.Hour, RefreshTTL: time.Hour,
		Upstreams:   map[string]config.Upstream{"jenkins": {URL: jenkins.URL}},
		CatalogFile: filepath.Join(dir, "catalog.json"),
	}
	h, err := buildHandler(cfg, st, oauth2.Endpoint{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = h
	ts.Start()
	defer ts.Close()

	// 1. An unauthenticated client is pointed at the OAuth metadata.
	resp, err := http.Post(pub+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), pub+"/.well-known/oauth-protected-resource") {
		t.Fatalf("unauthenticated: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}

	// 2. A signed-in user. The token is issued directly; internal/auth tests the OAuth flow itself.
	u, _ := st.UpsertUser(ctx, "rahmad@example.com")
	st.CreateClient(ctx, store.Client{ID: "c1", RedirectURIs: []string{"https://x/cb"}})
	sum := sha256.Sum256([]byte("e2e-access"))
	st.SaveToken(ctx, store.Token{Hash: sum[:], Kind: "access", ClientID: "c1", UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour)})
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "0"}, nil).Connect(ctx,
		&mcp.StreamableClientTransport{Endpoint: pub + "/mcp", HTTPClient: &http.Client{Transport: bearer("e2e-access")}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	call := func(name string, args map[string]any) (string, bool) {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		return res.Content[0].(*mcp.TextContent).Text, res.IsError
	}

	// 3. Jenkins is not connected yet.
	builds := map[string]any{"jobURL": jenkins.URL + "/job/app"}
	if text, isErr := call("jenkins_builds", builds); !isErr || text != "Jenkins is not connected. Connect it at "+pub+"/connect/jenkins" {
		t.Fatalf("before connect: %q", text)
	}

	// 4. Connect Jenkins through the web form.
	rec := httptest.NewRecorder()
	(&auth.Server{Signer: auth.NewSigner(cfg.SessionKey), PublicURL: pub}).SetSession(rec, u)
	req, _ := http.NewRequest("POST", pub+"/connect/jenkins", strings.NewReader(url.Values{"username": {"alice"}, "token": {"tok"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", pub)
	req.AddCookie(rec.Result().Cookies()[0])
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err = noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("connect: %d", resp.StatusCode)
	}

	// 5. The same tool call now reaches Jenkins with the user's credentials.
	if text, isErr := call("jenkins_builds", builds); isErr || !strings.Contains(text, "#7 SUCCESS") {
		t.Fatalf("after connect: %q", text)
	}

	// 6. Destructive tools are annotated.
	tl, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range tl.Tools {
		if x.Name == "jenkins_deploy" && (x.Annotations.DestructiveHint == nil || !*x.Annotations.DestructiveHint) {
			t.Error("jenkins_deploy is not marked destructive")
		}
		if strings.HasPrefix(x.Name, "argocd_") {
			t.Errorf("%s listed although ARGOCD_URL is unset", x.Name)
		}
	}

	// 7. A personal access token created on /tokens sees only its tools and acts
	// as its owner (with the Jenkins credentials connected above) within its scope.
	req, _ = http.NewRequest("POST", pub+"/tokens", strings.NewReader(url.Values{
		"name": {"atlas"}, "tools": {"jenkins_builds"}, "scope": {`{"jenkins":"app"}`}, "expiry": {"7"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", pub)
	req.AddCookie(rec.Result().Cookies()[0])
	resp, err = noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`<pre>(vk_[A-Z0-9]+)</pre>`).FindSubmatch(page)
	if resp.StatusCode != 200 || m == nil {
		t.Fatalf("create token: %d", resp.StatusCode)
	}
	pat, err := mcp.NewClient(&mcp.Implementation{Name: "atlas", Version: "0"}, nil).Connect(ctx,
		&mcp.StreamableClientTransport{Endpoint: pub + "/mcp", HTTPClient: &http.Client{Transport: bearer(string(m[1]))}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pat.Close()
	ptl, err := pat.ListTools(ctx, nil)
	if err != nil || len(ptl.Tools) != 1 {
		t.Fatalf("token tools/list: %v %v", ptl, err)
	}
	res, err := pat.CallTool(ctx, &mcp.CallToolParams{Name: "jenkins_builds", Arguments: builds})
	if err != nil || res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "#7 SUCCESS") {
		t.Fatalf("token in scope: %+v %v", res, err)
	}
	res, err = pat.CallTool(ctx, &mcp.CallToolParams{Name: "jenkins_builds", Arguments: map[string]any{"jobURL": jenkins.URL + "/job/other"}})
	if err != nil || !res.IsError || !strings.HasPrefix(res.Content[0].(*mcp.TextContent).Text, "refused:") {
		t.Fatalf("token out of scope: %+v %v", res, err)
	}
	if res, err := pat.CallTool(ctx, &mcp.CallToolParams{Name: "jenkins_deploy", Arguments: builds}); err == nil && !res.IsError {
		t.Fatal("token called a tool it was not given")
	}

	// 8. Health check.
	resp, _ = http.Get(pub + "/healthz")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("healthz: %d", resp.StatusCode)
	}
}
