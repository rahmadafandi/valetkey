package argocd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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
	mu       sync.Mutex
	statuses []string // returned in order; the last one repeats
	synced   bool
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
	mux.HandleFunc("GET /auth/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dex/auth/ldap?req=abc", http.StatusFound)
	})
	mux.HandleFunc("GET /dex/auth/ldap", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`<html><form method="post" action="/dex/auth/ldap/login?back=&amp;state=abc"><input name="login"></form></html>`))
	})
	mux.HandleFunc("POST /dex/auth/ldap/login", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.URL.Query().Get("state") == "abc" && r.PostForm.Get("login") == "alice" && r.PostForm.Get("password") == "pw" {
			http.SetCookie(w, &http.Cookie{Name: "argocd.token", Value: "tok", Path: "/"})
		}
		w.Write([]byte("done"))
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func setup(t *testing.T, statuses ...string) (*ArgoCD, *fakeArgo) {
	f := newFake(t, statuses...)
	a := New(f.URL, false)
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

func TestDexLogin(t *testing.T) {
	a, _ := setup(t, appJSON("Synced", "Healthy", "r1"))
	if got, err := a.bearer(ctx, tools.Creds{"username": "alice", "password": "pw"}); err != nil || got != "tok" {
		t.Fatalf("bearer = %q, %v", got, err)
	}
	if _, err := a.bearer(ctx, tools.Creds{"username": "alice", "password": "wrong"}); !errors.Is(err, upstream.ErrUnauthorized) {
		t.Errorf("wrong password: %v", err)
	}
	if _, err := a.bearer(ctx, tools.Creds{}); err == nil {
		t.Error("empty creds accepted")
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

// countingServer returns a server that counts every request it receives.
func countingServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Write([]byte(`<html><form method="post" action="/x"></form></html>`))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestDexLoginRefusesForeignFormAction(t *testing.T) {
	foreign, hits := countingServer(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dex/auth/ldap", http.StatusFound)
	})
	mux.HandleFunc("GET /dex/auth/ldap", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`<html><form method="post" action="` + foreign.URL + `/steal"></form></html>`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	a := New(srv.URL, false)
	_, err := a.bearer(ctx, tools.Creds{"username": "alice", "password": "pw"})
	if err == nil {
		t.Fatal("login to a foreign form action succeeded")
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("foreign server received %d requests", n)
	}
}

func TestDexLoginRefusesForeignRedirect(t *testing.T) {
	foreign, hits := countingServer(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, foreign.URL+"/dex/auth/ldap", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	a := New(srv.URL, false)
	_, err := a.bearer(ctx, tools.Creds{"username": "alice", "password": "pw"})
	if err == nil {
		t.Fatal("login through a foreign redirect succeeded")
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("foreign server received %d requests", n)
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
