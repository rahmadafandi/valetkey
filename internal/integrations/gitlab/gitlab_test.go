package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/upstream"
)

var (
	ctx   = context.Background()
	alice = tools.Creds{"token": "tok"}
)

const (
	// The project path travels as one escaped segment.
	projectBase = "/api/v4/projects/legal%2Fbots%2Flegal-bot-ai"
	head        = "441f3f9abcde0123456789abcdef0123456789ab"
)

func mr(iid int, state, source, target, sha string) string {
	return `{"iid":` + strconv.Itoa(iid) + `,"title":"Fix login","state":"` + state + `","author":{"name":"Atlas"},
	 "source_branch":"` + source + `","target_branch":"` + target + `","sha":"` + sha + `",
	 "web_url":"https://git.example.com/legal/bots/legal-bot-ai/-/merge_requests/` + strconv.Itoa(iid) + `"}`
}

type fake struct {
	*httptest.Server
	mu     sync.Mutex
	writes []string // "METHOD path body"
	open   string   // JSON array for the opened list
	mr7    string
}

func newFake(t *testing.T) *fake {
	f := &fake{open: `[]`, mr7: mr(7, "opened", "fix/login", "main", head)}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "tok" {
			http.Error(w, `{"message":"401 Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			b, _ := io.ReadAll(r.Body)
			f.mu.Lock()
			f.writes = append(f.writes, r.Method+" "+r.URL.EscapedPath()+" "+string(b))
			f.mu.Unlock()
		}
		q := r.URL.Query()
		switch r.Method + " " + r.URL.EscapedPath() {
		case "GET /api/v4/user":
			w.Write([]byte(`{"username":"atlas"}`))
		case "GET " + projectBase:
			w.Write([]byte(`{"default_branch":"main"}`))
		case "GET " + projectBase + "/merge_requests":
			if q.Get("state") != "opened" || q.Get("source_branch") != "fix/login" || q.Get("target_branch") != "main" {
				http.Error(w, "unexpected query "+r.URL.RawQuery, http.StatusBadRequest)
				return
			}
			w.Write([]byte(f.open))
		case "POST " + projectBase + "/merge_requests":
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(mr(8, "opened", "fix/login", "main", head)))
		case "GET " + projectBase + "/merge_requests/7":
			w.Write([]byte(f.mr7))
		case "GET " + projectBase + "/merge_requests/7/approvals":
			w.Write([]byte(`{"approved_by":[{"user":{"name":"Rahmad"}}]}`))
		case "GET " + projectBase + "/merge_requests/7/diffs":
			w.Write([]byte(`[{"old_path":"app/auth.py","new_path":"app/auth.py","diff":"@@ -1,2 +1,4 @@\n-old\n+fixed\n+two\n+three\n"},
			 {"old_path":"old.py","new_path":"old.py","deleted_file":true,"diff":"@@ -1 +0,0 @@\n-gone\n"}]`))
		case "PUT " + projectBase + "/merge_requests/7/merge":
			w.Write([]byte(strings.Replace(mr(7, "merged", "fix/login", "main", head), `"web_url"`, `"merge_commit_sha":"999aaa","web_url"`, 1)))
		case "POST " + projectBase + "/merge_requests/7/notes":
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"id":55}`))
		default:
			http.Error(w, `{"message":"404 Not Found"}`, http.StatusNotFound)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func setup(t *testing.T) (*GitLab, *fake) {
	f := newFake(t)
	return New(f.URL+"/", false), f
}

func run(t *testing.T, g *GitLab, name string, c tools.Creds, args string) (string, error) {
	t.Helper()
	for _, tl := range g.Tools() {
		if tl.Name == name {
			return tl.Run(ctx, c, json.RawMessage(args))
		}
	}
	t.Fatalf("no tool %s", name)
	return "", nil
}

const project = `"project":"legal/bots/legal-bot-ai"`

func TestValidate(t *testing.T) {
	g, _ := setup(t)
	if err := g.Validate(ctx, alice); err != nil {
		t.Errorf("good token: %v", err)
	}
	if err := g.Validate(ctx, tools.Creds{"token": "nope"}); !errors.Is(err, upstream.ErrUnauthorized) {
		t.Errorf("bad token: %v", err)
	}
	if err := g.Validate(ctx, tools.Creds{}); err == nil {
		t.Error("accepted an empty token")
	}
}

func TestCreateMR(t *testing.T) {
	g, f := setup(t)
	out, err := run(t, g, "gitlab_mr_create", alice, `{`+project+`,"source_branch":"fix/login","title":"Fix login","description":"why"}`)
	if err != nil || !strings.HasPrefix(out, "created:\nMR !8 opened") || !strings.Contains(out, "source commit "+head) {
		t.Fatalf("got %q %v", out, err)
	}
	if len(f.writes) != 1 || !strings.Contains(f.writes[0], `"target_branch":"main"`) || !strings.Contains(f.writes[0], `"source_branch":"fix/login"`) {
		t.Errorf("writes = %v", f.writes)
	}
}

func TestCreateMRIsIdempotent(t *testing.T) {
	g, f := setup(t)
	f.open = `[` + f.mr7 + `]`
	out, err := run(t, g, "gitlab_mr_create", alice, `{`+project+`,"source_branch":"fix/login","title":"Fix login"}`)
	if err != nil || !strings.HasPrefix(out, "already open") || !strings.Contains(out, "MR !7") {
		t.Fatalf("got %q %v", out, err)
	}
	if len(f.writes) != 0 {
		t.Errorf("created a duplicate: %v", f.writes)
	}
}

func TestCreateMRRefusesOtherDestination(t *testing.T) {
	g, f := setup(t)
	for _, args := range []string{
		`{` + project + `,"source_branch":"fix/login","title":"x","destination":"release"}`,
		`{` + project + `,"source_branch":"main","title":"x"}`,
	} {
		if _, err := run(t, g, "gitlab_mr_create", alice, args); err == nil || !strings.Contains(err.Error(), "refused") {
			t.Errorf("%s: %v", args, err)
		}
	}
	if len(f.writes) != 0 {
		t.Errorf("writes = %v", f.writes)
	}
}

func TestMRGet(t *testing.T) {
	g, _ := setup(t)
	out, err := run(t, g, "gitlab_mr_get", alice, `{`+project+`,"id":7}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"MR !7 opened: Fix login", "fix/login -> main, source commit " + head, "author Atlas",
		"approvals (1): Rahmad", "modified app/auth.py +3 -1", "removed old.py +0 -1"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestMRDiff(t *testing.T) {
	g, _ := setup(t)
	out, err := run(t, g, "gitlab_mr_diff", alice, `{`+project+`,"id":7}`)
	if err != nil || !strings.Contains(out, "diff --git a/app/auth.py b/app/auth.py\n--- a/app/auth.py\n+++ b/app/auth.py\n@@ -1,2 +1,4 @@\n-old\n+fixed") ||
		!strings.Contains(out, "+++ /dev/null") {
		t.Fatalf("got %q %v", out, err)
	}
}

func TestMerge(t *testing.T) {
	g, f := setup(t)
	out, err := run(t, g, "gitlab_mr_merge", alice, `{`+project+`,"id":7,"expected_source_commit":"441f3f9abcde","strategy":"squash"}`)
	if err != nil || !strings.HasPrefix(out, "merged:\nMR !7 merged") || !strings.Contains(out, "merge commit 999aaa") {
		t.Fatalf("got %q %v", out, err)
	}
	// GitLab itself refuses when the head is no longer the full sha sent here.
	if len(f.writes) != 1 || !strings.Contains(f.writes[0], `"sha":"`+head+`"`) || !strings.Contains(f.writes[0], `"squash":true`) ||
		!strings.Contains(f.writes[0], `"should_remove_source_branch":false`) {
		t.Errorf("writes = %v", f.writes)
	}
}

func TestMergeRefusals(t *testing.T) {
	cases := []struct {
		name, mr7, args, want string
	}{
		{"moved head", "", `"expected_source_commit":"0000000abcde"`, "not the reviewed"},
		{"short hash", "", `"expected_source_commit":"441f3f9"`, "at least 12"},
		{"missing hash", "", `"strategy":"merge_commit"`, "at least 12"},
		{"bad strategy", "", `"expected_source_commit":"441f3f9abcde","strategy":"fast_forward"`, "strategy"},
		{"other destination", mr(7, "opened", "fix/login", "release", head), `"expected_source_commit":"441f3f9abcde"`, "not the default branch"},
		{"already merged", mr(7, "merged", "fix/login", "main", head), `"expected_source_commit":"441f3f9abcde"`, "is merged"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, f := setup(t)
			if tc.mr7 != "" {
				f.mr7 = tc.mr7
			}
			_, err := run(t, g, "gitlab_mr_merge", alice, `{`+project+`,"id":7,`+tc.args+`}`)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
			if len(f.writes) != 0 {
				t.Errorf("merge was sent: %v", f.writes)
			}
		})
	}
}

func TestComment(t *testing.T) {
	g, f := setup(t)
	out, err := run(t, g, "gitlab_mr_comment", alice, `{`+project+`,"id":7,"text":"tests pass"}`)
	if err != nil || out != "comment 55 added to MR !7" {
		t.Fatalf("got %q %v", out, err)
	}
	if len(f.writes) != 1 || !strings.Contains(f.writes[0], `{"body":"tests pass"}`) {
		t.Errorf("writes = %v", f.writes)
	}
}

// A numeric project ID would reach a project the scope never named.
func TestRejectsBadProject(t *testing.T) {
	g, _ := setup(t)
	for _, p := range []string{"app", "42", "legal/../x", "../../user", "legal/app?x=1", "legal//app", "legal/app/", ""} {
		if _, err := run(t, g, "gitlab_mr_get", alice, `{"project":"`+p+`","id":7}`); err == nil {
			t.Errorf("accepted %q", p)
		}
	}
}

func TestWrongTokenIsUnauthorized(t *testing.T) {
	g, _ := setup(t)
	_, err := run(t, g, "gitlab_mr_get", tools.Creds{"token": "nope"}, `{`+project+`,"id":7}`)
	if !errors.Is(err, upstream.ErrUnauthorized) {
		t.Errorf("err = %v", err)
	}
}

func TestDestructiveFlags(t *testing.T) {
	g, _ := setup(t)
	want := map[string]bool{"gitlab_mr_create": true, "gitlab_mr_get": false, "gitlab_mr_diff": false, "gitlab_mr_merge": true, "gitlab_mr_comment": true}
	for _, tl := range g.Tools() {
		if d, ok := want[tl.Name]; !ok || d != tl.Destructive {
			t.Errorf("%s: known=%v destructive=%v", tl.Name, ok, tl.Destructive)
		}
		delete(want, tl.Name)
	}
	if len(want) != 0 {
		t.Errorf("missing tools: %v", want)
	}
}

func TestParseScope(t *testing.T) {
	g := &GitLab{}
	if v, err := g.ParseScope(json.RawMessage(`" legal/bots/legal-bot-ai "`)); err != nil || !slices.Equal(v.([]string), []string{"legal/bots/legal-bot-ai"}) {
		t.Errorf("project: %v %v", v, err)
	}
	if v, err := g.ParseScope(json.RawMessage(`["acme/web","acme/api"]`)); err != nil || !slices.Equal(v.([]string), []string{"acme/web", "acme/api"}) {
		t.Errorf("list: %v %v", v, err)
	}
	for _, bad := range []string{`3`, `""`, `null`, `[]`, `"acme"`, `"42"`, `["acme/web",""]`, `["acme/web","acme"]`, `"acme/*"`} {
		if _, err := g.ParseScope(json.RawMessage(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestCheckScope(t *testing.T) {
	g := &GitLab{}
	scope, err := g.ParseScope(json.RawMessage(`["acme/web","legal/bots/legal-bot-ai"]`))
	if err != nil {
		t.Fatal(err)
	}
	for args, ok := range map[string]bool{
		`{"project":"acme/web"}`:                true,
		`{"project":"legal/bots/legal-bot-ai"}`: true,
		`{"project":"acme/other"}`:              false,
		`{"project":"legal/bots"}`:              false,
		`{"project":"acme/web/"}`:               false,
		`{}`:                                    false,
		``:                                      false,
	} {
		err := g.CheckScope(scope, "gitlab_mr_merge", json.RawMessage(args))
		if (err == nil) != ok {
			t.Errorf("%s: err = %v, want ok=%v", args, err, ok)
		}
		if err != nil && !tools.IsRefusal(err) {
			t.Errorf("%s: not a refusal: %v", args, err)
		}
	}
}
