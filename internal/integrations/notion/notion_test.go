package notion

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

	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/upstream"
)

// The fake workspace:
//
//	pageA (workspace)
//	  pageB
//	    database D, data source S
//	      row R
//	pageX (workspace)
const (
	pageA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pageB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	dbD   = "dddddddddddddddddddddddddddddddd"
	dsS   = "55555555555555555555555555555555"
	rowR  = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	pageX = "ffffffffffffffffffffffffffffffff"
	// pageC is shared with the user, but its parent is not.
	pageC  = "cccccccccccccccccccccccccccccccc"
	hidden = "99999999999999999999999999999999"
)

var (
	ctx   = context.Background()
	alice = tools.Creds{"token": "tok"}
)

func dashed(id string) string {
	return id[:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:]
}

func pageJSON(id, parent, title string) string {
	return `{"object":"page","id":"` + dashed(id) + `","url":"https://www.notion.so/` + id + `","in_trash":false,"parent":` + parent +
		`,"properties":{"Name":{"type":"title","title":[{"plain_text":"` + title + `"}]},"Status":{"type":"status","status":{"name":"Done"}}}}`
}

func onPage(id string) string { return `{"type":"page_id","page_id":"` + dashed(id) + `"}` }

const workspace = `{"type":"workspace","workspace":true}`

type fake struct {
	*httptest.Server
	mu     sync.Mutex
	writes []string // "METHOD path body"
	gets   int
}

func newFake(t *testing.T) *fake {
	f := &fake{}
	pages := map[string]string{
		pageA: pageJSON(pageA, workspace, "Team"),
		pageB: pageJSON(pageB, onPage(pageA), "Ops"),
		rowR:  pageJSON(rowR, `{"type":"data_source_id","data_source_id":"`+dsS+`","database_id":"`+dbD+`"}`, "Deploy notes"),
		pageX: pageJSON(pageX, workspace, "Private"),
		pageC: pageJSON(pageC, onPage(hidden), "Shared with me"),
	}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			io.WriteString(w, `{"object":"error","status":401,"code":"unauthorized","message":"API token is invalid."}`)
			return
		}
		if r.Header.Get("Notion-Version") != apiVersion {
			w.WriteHeader(400)
			io.WriteString(w, `{"code":"missing_version","message":"bad version"}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		if r.Method == http.MethodGet {
			f.gets++
		} else if r.URL.Path != "/search" && !strings.HasSuffix(r.URL.Path, "/query") {
			f.writes = append(f.writes, r.Method+" "+r.URL.Path+" "+string(body))
		}
		f.mu.Unlock()
		p := r.URL.Path
		switch {
		case p == "/users/me":
			io.WriteString(w, `{"object":"user","type":"bot"}`)
		case r.Method == "GET" && strings.HasPrefix(p, "/pages/") && strings.HasSuffix(p, "/markdown"):
			io.WriteString(w, `{"object":"page_markdown","markdown":"## Steps\nRun it.","truncated":false}`)
		case r.Method == "GET" && strings.HasPrefix(p, "/pages/"):
			if j, ok := pages[strings.TrimPrefix(p, "/pages/")]; ok {
				io.WriteString(w, j)
				return
			}
			w.WriteHeader(404)
			io.WriteString(w, `{"code":"object_not_found","message":"Could not find page"}`)
		case p == "/databases/"+dbD:
			io.WriteString(w, `{"object":"database","id":"`+dashed(dbD)+`","title":[{"plain_text":"Runbooks"}],"parent":`+onPage(pageB)+`,"data_sources":[{"id":"`+dashed(dsS)+`","name":"Runbooks"}]}`)
		case p == "/data_sources/"+dsS && r.Method == "GET":
			io.WriteString(w, `{"object":"data_source","id":"`+dashed(dsS)+`","title":[{"plain_text":"Runbooks"}],"parent":{"type":"database_id","database_id":"`+dashed(dbD)+`"},"properties":{"Name":{"type":"title"},"Status":{"type":"status"}}}`)
		case p == "/data_sources/"+dsS+"/query":
			io.WriteString(w, `{"results":[`+pages[rowR]+`],"has_more":true,"next_cursor":"cur2"}`)
		case p == "/search":
			io.WriteString(w, `{"results":[`+pages[pageB]+`,`+pages[pageX]+`,{"object":"data_source","id":"`+dashed(dsS)+`","title":[{"plain_text":"Runbooks"}],"parent":{"type":"database_id","database_id":"`+dashed(dbD)+`"}}]}`)
		case p == "/pages" && r.Method == "POST":
			io.WriteString(w, `{"object":"page","id":"`+dashed(rowR)+`","url":"https://www.notion.so/new"}`)
		case r.Method == "PATCH" && strings.HasSuffix(p, "/markdown"):
			io.WriteString(w, `{"object":"page_markdown","markdown":"done"}`)
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"code":"object_not_found","message":"no route `+p+`"}`)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func tool(t *testing.T, n *Notion, name string) tools.Tool {
	for _, tl := range n.Tools() {
		if tl.Name == name {
			return tl
		}
	}
	t.Fatalf("no tool %s", name)
	return tools.Tool{}
}

func run(t *testing.T, n *Notion, ctx context.Context, name string, args map[string]any) (string, error) {
	raw, _ := json.Marshal(args)
	return tool(t, n, name).Run(ctx, alice, raw)
}

// scoped is a call made with a token whose scope lists ids.
func scoped(ids ...string) context.Context { return tools.WithScope(ctx, ids) }

func TestValidate(t *testing.T) {
	f := newFake(t)
	n := New(f.URL, false)
	if err := n.Validate(ctx, alice); err != nil {
		t.Errorf("good token: %v", err)
	}
	if err := n.Validate(ctx, tools.Creds{"token": "bad"}); !errors.Is(err, upstream.ErrUnauthorized) {
		t.Errorf("bad token: %v", err)
	}
	if err := n.Validate(ctx, tools.Creds{}); err == nil {
		t.Error("empty token accepted")
	}
}

func TestNormID(t *testing.T) {
	for in, want := range map[string]string{
		dashed(pageA):          pageA,
		strings.ToUpper(pageA): pageA,
		"https://www.notion.so/acme/Deploy-notes-" + rowR + "?pvs=4": rowR,
		"https://www.notion.so/acme/" + dbD + "?v=" + pageX:          dbD,
	} {
		if got, err := normID(in); err != nil || got != want {
			t.Errorf("normID(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := normID("not an id"); err == nil {
		t.Error("garbage accepted")
	}
}

func TestPageGet(t *testing.T) {
	n := New(newFake(t).URL, false)
	out, err := run(t, n, ctx, "notion_page_get", map[string]any{"page_id": "https://www.notion.so/x-" + rowR})
	if err != nil || !strings.Contains(out, "Deploy notes") || !strings.Contains(out, "Status: Done") || !strings.Contains(out, "## Steps") {
		t.Errorf("out = %q, %v", out, err)
	}
}

func TestScopeReachesWhatIsUnderAnAllowedPage(t *testing.T) {
	n := New(newFake(t).URL, false)
	// rowR sits in a database under pageB under pageA.
	if _, err := run(t, n, scoped(pageA), "notion_page_get", map[string]any{"page_id": rowR}); err != nil {
		t.Errorf("row under allowed page: %v", err)
	}
	if _, err := run(t, n, scoped(dbD), "notion_page_get", map[string]any{"page_id": rowR}); err != nil {
		t.Errorf("row in allowed database: %v", err)
	}
	_, err := run(t, n, scoped(pageB), "notion_page_get", map[string]any{"page_id": pageX})
	if !tools.IsRefusal(err) {
		t.Errorf("page outside scope: %v", err)
	}
	if _, err := run(t, n, scoped(rowR), "notion_page_get", map[string]any{"page_id": pageB}); !tools.IsRefusal(err) {
		t.Errorf("a parent of the allowed page: %v", err)
	}
}

func TestSearchHidesWhatIsOutsideScope(t *testing.T) {
	n := New(newFake(t).URL, false)
	out, err := run(t, n, ctx, "notion_search", map[string]any{"query": "o"})
	if err != nil || !strings.Contains(out, "Private") || !strings.Contains(out, "database "+dashed(dbD)) {
		t.Errorf("unscoped: %q, %v", out, err)
	}
	out, err = run(t, n, scoped(pageB), "notion_search", map[string]any{"query": "o"})
	if err != nil || strings.Contains(out, "Private") || !strings.Contains(out, "Ops") || !strings.Contains(out, "Runbooks") ||
		!strings.Contains(out, "1 more results are outside") {
		t.Errorf("scoped: %q, %v", out, err)
	}
}

func TestDatabaseQuery(t *testing.T) {
	n := New(newFake(t).URL, false)
	out, err := run(t, n, scoped(pageA), "notion_database_query", map[string]any{"database_id": dbD,
		"filter": map[string]any{"property": "Status", "status": map[string]string{"equals": "Done"}}})
	if err != nil || !strings.Contains(out, "Name: Deploy notes") || !strings.Contains(out, `start_cursor "cur2"`) {
		t.Errorf("out = %q, %v", out, err)
	}
	if _, err := run(t, n, scoped(pageX), "notion_database_query", map[string]any{"database_id": dbD}); !tools.IsRefusal(err) {
		t.Errorf("database outside scope: %v", err)
	}
}

func TestPageCreateInDatabaseUsesItsTitleProperty(t *testing.T) {
	f := newFake(t)
	n := New(f.URL, false)
	out, err := run(t, n, scoped(pageB), "notion_page_create", map[string]any{"parent_id": dbD, "parent_type": "database", "title": "Rollback", "markdown": "- step"})
	if err != nil || !strings.Contains(out, "created page") {
		t.Fatalf("out = %q, %v", out, err)
	}
	if len(f.writes) != 1 || !strings.Contains(f.writes[0], `"data_source_id":"`+dsS+`"`) || !strings.Contains(f.writes[0], `"Name":{"title"`) ||
		!strings.Contains(f.writes[0], `"markdown":"- step"`) {
		t.Errorf("writes = %v", f.writes)
	}
}

func TestPageCreateOutsideScopeWritesNothing(t *testing.T) {
	f := newFake(t)
	n := New(f.URL, false)
	if _, err := run(t, n, scoped(pageB), "notion_page_create", map[string]any{"parent_id": pageX, "parent_type": "page", "title": "x"}); !tools.IsRefusal(err) {
		t.Errorf("err = %v", err)
	}
	if _, err := run(t, n, scoped(pageB), "notion_page_append", map[string]any{"page_id": pageA, "markdown": "x"}); !tools.IsRefusal(err) {
		t.Errorf("append: %v", err)
	}
	if len(f.writes) != 0 {
		t.Errorf("writes = %v", f.writes)
	}
}

func TestPageAppend(t *testing.T) {
	f := newFake(t)
	n := New(f.URL, false)
	if _, err := run(t, n, ctx, "notion_page_append", map[string]any{"page_id": pageB, "markdown": "Done."}); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 1 || !strings.HasPrefix(f.writes[0], "PATCH /pages/"+pageB+"/markdown") || !strings.Contains(f.writes[0], `"position":{"type":"end"}`) {
		t.Errorf("writes = %v", f.writes)
	}
}

func TestForbiddenIsNotAReconnect(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		io.WriteString(w, `{"code":"restricted_resource","message":"Insufficient permissions"}`)
	}))
	defer ts.Close()
	_, err := New(ts.URL, false).getPage(ctx, alice, pageA)
	if err == nil || errors.Is(err, upstream.ErrUnauthorized) || !strings.Contains(err.Error(), "restricted_resource") {
		t.Errorf("err = %v", err)
	}
}

func TestParseScope(t *testing.T) {
	n := New("http://x", false)
	s, err := n.ParseScope(json.RawMessage(`["` + dashed(pageA) + `","https://www.notion.so/Ops-` + pageB + `"]`))
	if err != nil || strings.Join(s.([]string), ",") != pageA+","+pageB {
		t.Errorf("s = %v, %v", s, err)
	}
	if _, err := n.ParseScope(json.RawMessage(`"nope"`)); err == nil {
		t.Error("garbage scope accepted")
	}
}

func TestEveryWriteIsDestructive(t *testing.T) {
	for _, tl := range New("http://x", false).Tools() {
		writes := strings.HasSuffix(tl.Name, "_create") || strings.HasSuffix(tl.Name, "_append")
		if writes != tl.Destructive {
			t.Errorf("%s: Destructive = %v", tl.Name, tl.Destructive)
		}
	}
}

func TestParentYouCannotOpenIsOutsideScope(t *testing.T) {
	n := New(newFake(t).URL, false)
	if _, err := run(t, n, scoped(pageA), "notion_page_get", map[string]any{"page_id": pageC}); !tools.IsRefusal(err) {
		t.Errorf("err = %v", err)
	}
	_, err := run(t, n, scoped(pageA), "notion_page_get", map[string]any{"page_id": hidden})
	if tools.IsRefusal(err) || err == nil || !strings.Contains(err.Error(), hidden) {
		t.Errorf("a missing page itself should say which: %v", err)
	}
}

func TestScopeMayListTheDataSource(t *testing.T) {
	n := New(newFake(t).URL, false)
	if _, err := run(t, n, scoped(dsS), "notion_database_query", map[string]any{"database_id": dbD}); err != nil {
		t.Errorf("query: %v", err)
	}
	if _, err := run(t, n, scoped(dsS), "notion_page_create", map[string]any{"parent_id": dbD, "parent_type": "database", "title": "x"}); err != nil {
		t.Errorf("create: %v", err)
	}
}

func TestObjectTagsAreRefusedForTokens(t *testing.T) {
	f := newFake(t)
	n := New(f.URL, false)
	md := `See <page url="https://www.notion.so/` + pageX + `">Private</page>`
	if _, err := run(t, n, scoped(pageA), "notion_page_append", map[string]any{"page_id": pageB, "markdown": md}); !tools.IsRefusal(err) {
		t.Errorf("token: %v", err)
	}
	if _, err := run(t, n, ctx, "notion_page_append", map[string]any{"page_id": pageB, "markdown": md}); err != nil {
		t.Errorf("signed-in client: %v", err)
	}
}

func TestWalkStopsAtItsBudget(t *testing.T) {
	n := New(newFake(t).URL, false)
	// rowR needs lookups for itself, its data source and its database before pageB.
	if _, err := n.within(scoped(pageA), alice, "page", rowR, newWalk(2)); !errors.Is(err, errOverBudget) {
		t.Errorf("err = %v", err)
	}
	if ok, err := n.within(scoped(pageA), alice, "page", rowR, newWalk(10)); !ok || err != nil {
		t.Errorf("enough budget: %v, %v", ok, err)
	}
}

func TestRateLimitSaysWhen(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(429)
	}))
	defer ts.Close()
	if _, err := New(ts.URL, false).getPage(ctx, alice, pageA); err == nil || !strings.Contains(err.Error(), "try again in 7 seconds") {
		t.Errorf("err = %v", err)
	}
}

// twoWorkspaces answers token "a" with workspace Acme, which holds pageA, and
// token "b" with workspace Beta, which holds pageB.
func twoWorkspaces(t *testing.T) *httptest.Server {
	type space struct{ name, page, title string }
	spaces := map[string]space{"Bearer a": {"Acme", pageA, "Team"}, "Bearer b": {"Beta", pageB, "Ops"}}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := spaces[r.Header.Get("Authorization")]
		switch {
		case !ok:
			w.WriteHeader(401)
			io.WriteString(w, `{"code":"unauthorized","message":"API token is invalid."}`)
		case r.URL.Path == "/users/me":
			io.WriteString(w, `{"object":"user","type":"bot","bot":{"workspace_name":"`+s.name+`"}}`)
		case r.URL.Path == "/search":
			io.WriteString(w, `{"results":[`+pageJSON(s.page, workspace, s.title)+`]}`)
		case r.URL.Path == "/pages/"+s.page:
			io.WriteString(w, pageJSON(s.page, workspace, s.title))
		case r.URL.Path == "/pages/"+s.page+"/markdown":
			io.WriteString(w, `{"markdown":"in `+s.name+`"}`)
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"code":"object_not_found","message":"Could not find it"}`)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestWorkspaces(t *testing.T) {
	n := New(twoWorkspaces(t).URL, false)
	c := tools.Creds{"token": "a", "token2": "b"}
	if err := n.Validate(ctx, c); err != nil || c["name"] != "Acme" || c["name2"] != "Beta" {
		t.Fatalf("validate: %v %v", c, err)
	}
	if err := n.Validate(ctx, tools.Creds{"token": "a", "token3": "bad"}); err == nil || !strings.Contains(err.Error(), "workspace 3") {
		t.Errorf("bad third token: %v", err)
	}
	raw, _ := json.Marshal(map[string]any{"query": ""})
	out, err := tool(t, n, "notion_search").Run(ctx, c, raw)
	if err != nil || !strings.Contains(out, `[Acme] page `+dashed(pageA)) || !strings.Contains(out, `[Beta] page `+dashed(pageB)) {
		t.Errorf("search: %q, %v", out, err)
	}
	for id, want := range map[string]string{pageA: "in Acme", pageB: "in Beta"} {
		raw, _ := json.Marshal(map[string]any{"page_id": id})
		if out, err := tool(t, n, "notion_page_get").Run(ctx, c, raw); err != nil || !strings.Contains(out, want) {
			t.Errorf("get %s: %q, %v", id, out, err)
		}
		// The token scope still applies, in whichever workspace the page is.
		if _, err := tool(t, n, "notion_page_get").Run(scoped(pageX), c, raw); !tools.IsRefusal(err) {
			t.Errorf("scoped get %s: %v", id, err)
		}
	}
	raw, _ = json.Marshal(map[string]any{"page_id": pageX})
	if _, err := tool(t, n, "notion_page_get").Run(ctx, c, raw); !errors.Is(err, errNotFound) {
		t.Errorf("in no workspace: %v", err)
	}
}
