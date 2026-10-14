package bitbucket

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/upstream"
)

var (
	ctx   = context.Background()
	alice = tools.Creds{"token": "tok"}
)

const repoBase = "/repositories/acme/web"

func pr(id int, state, source, dest, hash string) string {
	return `{"id":` + itoa(id) + `,"title":"Fix login","state":"` + state + `","author":{"display_name":"Atlas"},
	 "source":{"branch":{"name":"` + source + `"},"commit":{"hash":"` + hash + `"}},
	 "destination":{"branch":{"name":"` + dest + `"}},
	 "participants":[{"user":{"display_name":"Rahmad"},"approved":true},{"user":{"display_name":"Bob"},"approved":false,"state":"changes_requested"}],
	 "links":{"html":{"href":"https://bitbucket.org/acme/web/pull-requests/` + itoa(id) + `"}}}`
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

type fake struct {
	*httptest.Server
	mu        sync.Mutex
	posts     []string // "path body"
	openPRs   string   // JSON array for the OPEN list
	pr7       string
	mergeCode int
	taskPolls int
}

func newFake(t *testing.T) *fake {
	f := &fake{openPRs: `[]`, pr7: pr(7, "OPEN", "fix/login", "master", "441f3f9abcde"), mergeCode: http.StatusOK}
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer tok" {
				if u, p, ok := r.BasicAuth(); !ok || u != "alice@example.com" || p != "tok" {
					http.Error(w, `{"error":{"message":"Unauthorized"}}`, http.StatusUnauthorized)
					return
				}
			}
			h(w, r)
		}
	}
	record := func(r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.posts = append(f.posts, r.URL.Path+" "+string(b))
		f.mu.Unlock()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+repoBase, auth(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"mainbranch":{"name":"master"}}`))
	}))
	mux.HandleFunc("GET "+repoBase+"/pullrequests", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != "OPEN" || r.URL.Query().Get("q") != `source.branch.name="fix/login"` {
			http.Error(w, "unexpected query "+r.URL.RawQuery, http.StatusBadRequest)
			return
		}
		w.Write([]byte(`{"values":` + f.openPRs + `}`))
	}))
	mux.HandleFunc("POST "+repoBase+"/pullrequests", auth(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(pr(8, "OPEN", "fix/login", "master", "441f3f9abcde")))
	}))
	mux.HandleFunc("GET "+repoBase+"/pullrequests/7", auth(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(f.pr7)) }))
	mux.HandleFunc("GET "+repoBase+"/pullrequests/7/diffstat", auth(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"values":[{"status":"modified","lines_added":3,"lines_removed":1,"old":{"path":"app/auth.py"},"new":{"path":"app/auth.py"}},
		 {"status":"removed","lines_added":0,"lines_removed":9,"old":{"path":"old.py"},"new":null}]}`))
	}))
	mux.HandleFunc("GET "+repoBase+"/pullrequests/7/diff", auth(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("diff --git a/app/auth.py b/app/auth.py\n+fixed\n"))
	}))
	mux.HandleFunc("POST "+repoBase+"/pullrequests/7/merge", auth(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		if f.mergeCode == http.StatusAccepted {
			w.Header().Set("Location", "https://evil.example"+repoBase+"/pullrequests/7/merge/task-status/t-1")
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Write([]byte(strings.Replace(pr(7, "MERGED", "fix/login", "master", "441f3f9abcde"), `"links"`, `"merge_commit":{"hash":"999aaa"},"links"`, 1)))
	}))
	mux.HandleFunc("GET "+repoBase+"/pullrequests/7/merge/task-status/t-1", auth(func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		f.taskPolls++
		n := f.taskPolls
		f.mu.Unlock()
		if n < 2 {
			w.Write([]byte(`{"task_status":"PENDING"}`))
			return
		}
		w.Write([]byte(`{"task_status":"SUCCESS","merge_result":` + pr(7, "MERGED", "fix/login", "master", "441f3f9abcde") + `}`))
	}))
	mux.HandleFunc("POST "+repoBase+"/pullrequests/7/comments", auth(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":55,"links":{"html":{"href":"https://bitbucket.org/c/55"}}}`))
	}))
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func setup(t *testing.T) (*Bitbucket, *fake) {
	mergePoll = time.Millisecond
	f := newFake(t)
	return New(f.URL+"/", false), f
}

func run(t *testing.T, b *Bitbucket, name string, c tools.Creds, args string) (string, error) {
	t.Helper()
	for _, tl := range b.Tools() {
		if tl.Name == name {
			return tl.Run(ctx, c, json.RawMessage(args))
		}
	}
	t.Fatalf("no tool %s", name)
	return "", nil
}

func TestCreatePR(t *testing.T) {
	b, f := setup(t)
	out, err := run(t, b, "bitbucket_pr_create", alice, `{"repo":"acme/web","source_branch":"fix/login","title":"Fix login","description":"why"}`)
	if err != nil || !strings.HasPrefix(out, "created:\nPR #8 OPEN") || !strings.Contains(out, "source commit 441f3f9abcde") {
		t.Fatalf("got %q %v", out, err)
	}
	if len(f.posts) != 1 || !strings.Contains(f.posts[0], `"destination":{"branch":{"name":"master"}}`) || !strings.Contains(f.posts[0], `"source":{"branch":{"name":"fix/login"}}`) {
		t.Errorf("posts = %v", f.posts)
	}
}

func TestCreatePRIsIdempotent(t *testing.T) {
	b, f := setup(t)
	f.openPRs = `[` + pr(7, "OPEN", "fix/login", "master", "441f3f9abcde") + `]`
	out, err := run(t, b, "bitbucket_pr_create", alice, `{"repo":"acme/web","source_branch":"fix/login","title":"Fix login"}`)
	if err != nil || !strings.HasPrefix(out, "already open") || !strings.Contains(out, "PR #7") {
		t.Fatalf("got %q %v", out, err)
	}
	if len(f.posts) != 0 {
		t.Errorf("created a duplicate: %v", f.posts)
	}
}

func TestCreatePRRefusesOtherDestination(t *testing.T) {
	b, f := setup(t)
	for _, args := range []string{
		`{"repo":"acme/web","source_branch":"fix/login","title":"x","destination":"release"}`,
		`{"repo":"acme/web","source_branch":"master","title":"x"}`,
	} {
		if _, err := run(t, b, "bitbucket_pr_create", alice, args); err == nil || !strings.Contains(err.Error(), "refused") {
			t.Errorf("%s: %v", args, err)
		}
	}
	if len(f.posts) != 0 {
		t.Errorf("posts = %v", f.posts)
	}
}

func TestPRGet(t *testing.T) {
	b, _ := setup(t)
	out, err := run(t, b, "bitbucket_pr_get", tools.Creds{"token": "tok", "email": "alice@example.com"}, `{"repo":"acme/web","id":7}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"PR #7 OPEN: Fix login", "fix/login -> master, source commit 441f3f9abcde", "approvals (1): Rahmad",
		"changes requested by Bob", "modified app/auth.py +3 -1", "removed old.py +0 -9"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestPRDiff(t *testing.T) {
	b, _ := setup(t)
	out, err := run(t, b, "bitbucket_pr_diff", alice, `{"repo":"acme/web","id":7}`)
	if err != nil || !strings.Contains(out, "+fixed") {
		t.Fatalf("got %q %v", out, err)
	}
}

func TestMerge(t *testing.T) {
	b, f := setup(t)
	out, err := run(t, b, "bitbucket_pr_merge", alice, `{"repo":"acme/web","id":7,"expected_source_commit":"441f3f9abcde0123456789abcdef0123456789ab","strategy":"squash"}`)
	if err != nil || !strings.HasPrefix(out, "merged:\nPR #7 MERGED") || !strings.Contains(out, "merge commit 999aaa") {
		t.Fatalf("got %q %v", out, err)
	}
	if len(f.posts) != 1 || !strings.Contains(f.posts[0], `"merge_strategy":"squash"`) || !strings.Contains(f.posts[0], `"close_source_branch":false`) {
		t.Errorf("posts = %v", f.posts)
	}
}

func TestMergeAsync(t *testing.T) {
	b, f := setup(t)
	f.mergeCode = http.StatusAccepted
	out, err := run(t, b, "bitbucket_pr_merge", alice, `{"repo":"acme/web","id":7,"expected_source_commit":"441f3f9abcde"}`)
	if err != nil || !strings.HasPrefix(out, "merged:\nPR #7 MERGED") || f.taskPolls != 2 {
		t.Fatalf("got %q %v (polls %d)", out, err, f.taskPolls)
	}
}

func TestMergeRefusals(t *testing.T) {
	cases := []struct {
		name, pr7, args, want string
	}{
		{"moved head", "", `"expected_source_commit":"0000000abcde"`, "not the reviewed"},
		{"short hash", "", `"expected_source_commit":"441f3f9"`, "at least 12"},
		{"missing hash", "", `"strategy":"merge_commit"`, "at least 12"},
		{"bad strategy", "", `"expected_source_commit":"441f3f9abcde","strategy":"fast_forward"`, "strategy"},
		{"other destination", pr(7, "OPEN", "fix/login", "release", "441f3f9abcde"), `"expected_source_commit":"441f3f9abcde"`, "not the main branch"},
		{"already merged", pr(7, "MERGED", "fix/login", "master", "441f3f9abcde"), `"expected_source_commit":"441f3f9abcde"`, "is MERGED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, f := setup(t)
			if tc.pr7 != "" {
				f.pr7 = tc.pr7
			}
			_, err := run(t, b, "bitbucket_pr_merge", alice, `{"repo":"acme/web","id":7,`+tc.args+`}`)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
			if len(f.posts) != 0 {
				t.Errorf("merge was sent: %v", f.posts)
			}
		})
	}
}

func TestComment(t *testing.T) {
	b, f := setup(t)
	out, err := run(t, b, "bitbucket_pr_comment", alice, `{"repo":"acme/web","id":7,"text":"tests pass"}`)
	if err != nil || out != "comment 55 added: https://bitbucket.org/c/55" {
		t.Fatalf("got %q %v", out, err)
	}
	if len(f.posts) != 1 || !strings.Contains(f.posts[0], `{"content":{"raw":"tests pass"}}`) {
		t.Errorf("posts = %v", f.posts)
	}
}

func TestRejectsBadRepo(t *testing.T) {
	b, _ := setup(t)
	for _, r := range []string{"app", "acme/web/../x", "../../user", "acme/web?x=1", "acme/../app", ""} {
		if _, err := run(t, b, "bitbucket_pr_get", alice, `{"repo":"`+r+`","id":7}`); err == nil {
			t.Errorf("accepted %q", r)
		}
	}
}

func TestWrongTokenIsUnauthorized(t *testing.T) {
	b, _ := setup(t)
	_, err := run(t, b, "bitbucket_pr_get", tools.Creds{"token": "nope"}, `{"repo":"acme/web","id":7}`)
	if !errors.Is(err, upstream.ErrUnauthorized) {
		t.Errorf("err = %v", err)
	}
}

func TestDestructiveFlags(t *testing.T) {
	b, _ := setup(t)
	want := map[string]bool{"bitbucket_pr_create": true, "bitbucket_pr_get": false, "bitbucket_pr_diff": false, "bitbucket_pr_merge": true, "bitbucket_pr_comment": true}
	for _, tl := range b.Tools() {
		if d, ok := want[tl.Name]; !ok || d != tl.Destructive {
			t.Errorf("%s: known=%v destructive=%v", tl.Name, ok, tl.Destructive)
		}
		delete(want, tl.Name)
	}
	if len(want) != 0 {
		t.Errorf("missing tools: %v", want)
	}
}
