package argocd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/upstream"
)

var ctx = context.Background()

func appJSON(sync, health, rev string, images ...string) string {
	b, _ := json.Marshal(map[string]any{"status": map[string]any{
		"sync":           map[string]any{"status": sync, "revision": rev},
		"health":         map[string]any{"status": health},
		"summary":        map[string]any{"images": images},
		"operationState": map[string]any{"phase": "Succeeded", "message": "ok", "finishedAt": "2026-10-14T03:00:00Z"},
		"resources":      []any{map[string]any{"status": "Synced", "health": map[string]any{"status": health}}},
	}})
	return string(b)
}

type fakeArgo struct {
	*httptest.Server
	mu        sync.Mutex
	statuses  []string // returned in order; the last one repeats
	synced    bool
	challenge string // code_challenge of the sign-in link the test followed
	syncs    int
	syncBody string // body of the last sync POST
}

func newFake(t *testing.T, statuses ...string) *fakeArgo {
	f := &fakeArgo{statuses: statuses}
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer tok" {
				http.Error(w, `{"error":"invalid session"}`, http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/applications/web", authed(func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Write([]byte(f.statuses[0]))
		if len(f.statuses) > 1 {
			f.statuses = f.statuses[1:]
		}
	}))
	mux.HandleFunc("POST /api/v1/applications/web/sync", authed(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.syncBody = string(body)
		f.synced = true
		f.syncs++
		f.mu.Unlock()
		w.Write([]byte(`{}`))
	}))
	mux.HandleFunc("GET /api/v1/session/userinfo", authed(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"loggedIn":true,"username":"alice"}`))
	}))
	mux.HandleFunc("POST /api/dex/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		challenge := f.challenge
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("client_id") != "argo-cd-cli" ||
			r.PostForm.Get("redirect_uri") != "http://localhost:8085/auth/callback" || r.PostForm.Get("code") != "c1" ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		w.Write([]byte(`{"id_token":"tok","access_token":"x","refresh_token":"r","token_type":"bearer","expires_in":86399}`))
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func setup(t *testing.T, statuses ...string) (*ArgoCD, *fakeArgo) {
	f := newFake(t, statuses...)
	a := New(f.URL, false, []byte("test-key-test-key-test-key-12345"))
	a.pollEvery = time.Millisecond
	return a, f
}

var tok = tools.Creds{"token": "tok"}

func run(t *testing.T, a *ArgoCD, name string, c tools.Creds, args string) (string, error) {
	t.Helper()
	for _, tl := range a.Tools() {
		if tl.Name == name {
			return tl.Run(ctx, c, json.RawMessage(args))
		}
	}
	t.Fatalf("no tool %s", name)
	return "", nil
}

func TestStatus(t *testing.T) {
	a, _ := setup(t, appJSON("Synced", "Healthy", "abcdef1234567", "img:v1"))
	out, err := run(t, a, "argocd_status", tok, `{"app":"web"}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"sync=Synced health=Healthy revision=abcdef1234", "resources=[1/1 synced · 1 healthy]", "img:v1"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
}

func TestSignInAndExchange(t *testing.T) {
	a, f := setup(t, appJSON("Synced", "Healthy", "r1"))
	link, err := url.Parse(a.SignInURL())
	if err != nil {
		t.Fatal(err)
	}
	q := link.Query()
	if link.Path != "/api/dex/auth" || q.Get("client_id") != "argo-cd-cli" || q.Get("redirect_uri") != "http://localhost:8085/auth/callback" ||
		q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" || !strings.Contains(q.Get("scope"), "openid") || q.Get("state") == "" {
		t.Fatalf("sign-in link %s", link)
	}
	if again, _ := url.Parse(a.SignInURL()); again.Query().Get("state") == q.Get("state") {
		t.Error("two sign-in links share a state")
	}
	f.mu.Lock()
	f.challenge = q.Get("code_challenge")
	f.mu.Unlock()
	c, err := a.Exchange(ctx, tools.Creds{"callback": " http://localhost:8085/auth/callback?code=c1&state=" + q.Get("state") + " "})
	if err != nil || len(c) != 1 || c["token"] != "tok" {
		t.Fatalf("exchange = %v, %v", c, err)
	}
	if err := a.Validate(ctx, c); err != nil {
		t.Errorf("exchanged token: %v", err)
	}
	// Another state derives another verifier, so a forged or reused link fails at Dex.
	if _, err := a.Exchange(ctx, tools.Creds{"callback": "http://localhost:8085/auth/callback?code=c1&state=forged"}); err == nil || !strings.Contains(err.Error(), "sign in again") {
		t.Errorf("forged state: %v", err)
	}
	if _, err := a.Exchange(ctx, tools.Creds{"callback": "http://localhost:8085/auth/callback?error=access_denied&state=x"}); err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Errorf("denied sign-in: %v", err)
	}
	if _, err := a.Exchange(ctx, tools.Creds{"callback": "not a url at all"}); err == nil {
		t.Error("a pasted value without a code was accepted")
	}
	if c, err := a.Exchange(ctx, tools.Creds{"token": "tok"}); err != nil || c["token"] != "tok" {
		t.Errorf("an API token is kept as it is: %v, %v", c, err)
	}
}

func TestPasswordLoginIsGone(t *testing.T) {
	a, _ := setup(t, appJSON("Synced", "Healthy", "r1"))
	for _, f := range a.Fields() {
		if f.Name == "username" || f.Name == "password" {
			t.Errorf("field %s is still offered", f.Name)
		}
	}
	if err := a.Validate(ctx, tools.Creds{"username": "alice", "password": "pw"}); err == nil {
		t.Error("a stored username and password still validate")
	}
}

func TestValidate(t *testing.T) {
	a, _ := setup(t, appJSON("Synced", "Healthy", "r1"))
	if err := a.Validate(ctx, tok); err != nil {
		t.Errorf("token: %v", err)
	}
	if err := a.Validate(ctx, tools.Creds{"token": "bad"}); !errors.Is(err, upstream.ErrUnauthorized) {
		t.Errorf("bad token: %v", err)
	}
}

func TestSync(t *testing.T) {
	a, f := setup(t, appJSON("Synced", "Healthy", "r2", "img:v2"))
	out, err := run(t, a, "argocd_sync", tok, `{"app":"web"}`)
	if err != nil || !strings.HasPrefix(out, "sync triggered.\n") || !f.synced {
		t.Errorf("out=%q err=%v synced=%v", out, err, f.synced)
	}
}

func TestWatchSuccess(t *testing.T) {
	v1 := appJSON("Synced", "Healthy", "r1", "img:v1")
	a, _ := setup(t, v1, v1, appJSON("OutOfSync", "Progressing", "r2", "img:v2"), appJSON("Synced", "Healthy", "r2", "img:v2"))
	out, err := a.watch(ctx, "tok", "web", time.Second)
	if err != nil || !strings.Contains(out, "success") || !strings.Contains(out, "img:v2") {
		t.Errorf("out=%q err=%v", out, err)
	}
}

func TestWatchDegraded(t *testing.T) {
	a, _ := setup(t, appJSON("Synced", "Healthy", "r1", "img:v1"), appJSON("Synced", "Degraded", "r2", "img:v2"))
	if out, err := a.watch(ctx, "tok", "web", time.Second); err != nil || !strings.Contains(out, "degraded") {
		t.Errorf("out=%q err=%v", out, err)
	}
}

func TestWatchTimeout(t *testing.T) {
	a, _ := setup(t, appJSON("Synced", "Healthy", "r1", "img:v1"))
	if out, err := a.watch(ctx, "tok", "web", 30*time.Millisecond); err != nil || !strings.Contains(out, "timeout") {
		t.Errorf("out=%q err=%v", out, err)
	}
}

func TestWatchUnauthorizedStopsAtOnce(t *testing.T) {
	a, _ := setup(t, appJSON("Synced", "Healthy", "r1"))
	start := time.Now()
	if _, err := a.watch(ctx, "bad", "web", time.Minute); !errors.Is(err, upstream.ErrUnauthorized) {
		t.Errorf("err = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("watch kept polling after a 401")
	}
}

func TestWatchToolLimits(t *testing.T) {
	a, _ := setup(t, appJSON("Synced", "Healthy", "r1"))
	for _, tl := range a.Tools() {
		if tl.Name == "argocd_watch" && tl.Timeout != 6*time.Minute {
			t.Errorf("argocd_watch timeout = %v", tl.Timeout)
		}
		if tl.Name == "argocd_sync" && !tl.Destructive {
			t.Error("argocd_sync must be destructive")
		}
	}
	if got := watchMinutes(0); got != 3 {
		t.Errorf("default = %d", got)
	}
	if got := watchMinutes(30); got != 5 {
		t.Errorf("cap = %d", got)
	}
}

func TestSyncSucceedsEvenIfStatusReadFails(t *testing.T) {
	a, f := setup(t, "not json")
	out, err := run(t, a, "argocd_sync", tok, `{"app":"web"}`)
	if err != nil || !strings.HasPrefix(out, "sync triggered (status unavailable: ") || !f.synced {
		t.Errorf("out=%q err=%v synced=%v", out, err, f.synced)
	}
}

func TestSyncExpectedRevision(t *testing.T) {
	const full = "0123456789abcdef0123456789abcdef01234567"
	cases := []struct {
		name, args, wantErr string
		refused             bool
		syncs               int
		body                string // sync POST body
	}{
		{"match", `{"app":"web","expected_revision":"0123456"}`, "", false, 1, `{"revision":"` + full + `"}`},
		{"mismatch", `{"app":"web","expected_revision":"fffffff"}`, "0123456789", true, 0, ""},
		{"too short", `{"app":"web","expected_revision":"0123"}`, "expected_revision needs at least 7 characters", false, 0, ""},
		{"omitted", `{"app":"web"}`, "", false, 1, "{}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, f := setup(t, appJSON("Synced", "Healthy", full, "img:v2"))
			out, err := run(t, a, "argocd_sync", tok, tc.args)
			if f.syncs != tc.syncs {
				t.Errorf("sync POSTs = %d, want %d", f.syncs, tc.syncs)
			}
			if f.syncBody != tc.body {
				t.Errorf("sync body = %q, want %q", f.syncBody, tc.body)
			}
			if tc.wantErr == "" {
				if err != nil || !strings.Contains(out, "sync triggered") {
					t.Errorf("out=%q err=%v", out, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || tools.IsRefusal(err) != tc.refused {
				t.Errorf("err=%v refused=%v", err, tools.IsRefusal(err))
			}
			if tc.refused && !strings.HasPrefix(err.Error(), "refused: argocd_sync: ") {
				t.Errorf("err=%v", err)
			}
		})
	}
}
