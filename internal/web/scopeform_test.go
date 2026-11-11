package web

import (
	"context"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rahmadafandi/valetkey/internal/auth"
	"github.com/rahmadafandi/valetkey/internal/tools"
)

func TestScopeInputStored(t *testing.T) {
	raw, err := inputFromForm(url.Values{
		"scope.loki":      {"{a=\"b\"}\r\n\n{e=\"f\"}\n"},
		"scope.bitbucket": {" acme/x \n"},
		"scope.jenkins":   {"  \n"},
		"arg.metabase":    {"database_id", "", "card_id"},
		"vals.metabase":   {"5\n7", "", "12"},
	}).stored()
	if err != nil {
		t.Fatal(err)
	}
	// One value is stored as a string, so an integration that takes exactly one accepts it.
	want := `{"bitbucket":"acme/x","loki":["{a=\"b\"}","{e=\"f\"}"],"metabase":{"card_id":["12"],"database_id":["5","7"]}}`
	if string(raw) != want {
		t.Errorf("stored %s", raw)
	}
	if raw, err := inputFromForm(url.Values{"arg.metabase": {""}, "vals.metabase": {""}}).stored(); err != nil || string(raw) != "{}" {
		t.Errorf("only a spare row: %s %v", raw, err)
	}
	back := inputFromStored([]byte(want))
	if back.Families["loki"] != "{a=\"b\"}\n{e=\"f\"}" || back.Families["bitbucket"] != "acme/x" ||
		!reflect.DeepEqual(back.Rows["metabase"], []scopeRow{{Arg: "card_id", Values: "12"}, {Arg: "database_id", Values: "5\n7"}}) {
		t.Errorf("read back %+v", back)
	}
	if got := inputFromStored([]byte(`not json`)); len(got.Families)+len(got.Rows) != 0 {
		t.Errorf("unreadable scope: %+v", got)
	}
}

func TestScopeFormRefusesHalfRows(t *testing.T) {
	if _, err := inputFromForm(url.Values{"arg.mb": {"database_id"}, "vals.mb": {"  \n"}}).stored(); err == nil || !strings.Contains(err.Error(), "Add at least one value for database_id") {
		t.Errorf("argument without values: %v", err)
	}
	if _, err := inputFromForm(url.Values{"arg.mb": {""}, "vals.mb": {"5"}}).stored(); err == nil || !strings.Contains(err.Error(), "Pick an argument") {
		t.Errorf("values without argument: %v", err)
	}
}

// scopedServer adds the user's server srv with tools q (database_id) and free (no arguments), approved.
func scopedServer(t *testing.T, e *env) {
	t.Helper()
	f := newMCPFake(t, &mcpFake{})
	q := tool("q", "Queries.", true)
	q.InputSchema = map[string]any{"type": "object", "properties": map[string]any{
		"query":       map[string]any{"type": "object", "properties": map[string]any{"database_id": map[string]any{"type": "integer"}}},
		"database_id": map[string]any{"type": "integer"},
	}}
	f.set(q, tool("free", "Free.", true))
	id, body := e.addNone(t, "srv", f.URL)
	e.do(t, "POST", "/upstreams/"+id+"/approve", url.Values{"digest": {digestOf(t, body)}}, e.cookie)
}

// storedScope parses a token's stored scope; a database may reformat its text.
func storedScope(t *testing.T, e *env, raw []byte) tools.Scope {
	t.Helper()
	s, err := tools.ParseScope(e.web.Integrations, raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTokenFormScopeFields(t *testing.T) {
	e := newEnv(t)
	scopedServer(t, e)
	_, page := e.get(t, "/tokens", true)
	for _, want := range []string{`name="scope.fake"`, `name="arg.srv"`, `<option value="database_id"`, `value="srv__q"`,
		`data-args="database_id query.database_id"`, `id="scope-script"`} {
		if !strings.Contains(page, want) {
			t.Errorf("/tokens misses %s", want)
		}
	}
	if strings.Contains(page, `name="scope"`) {
		t.Error("/tokens still has the JSON scope box")
	}
	form := url.Values{"name": {"bot"}, "expiry": {"30"}, "tools": {"srv__q", "srv__free"}, "arg.srv": {"database_id", ""}, "vals.srv": {"5", ""}}
	if code, body := e.post(t, "/tokens", form, e.url); code != 200 {
		t.Fatalf("create: %d\n%s", code, body)
	}
	list, _ := e.as.Store.ListPersonalTokens(context.Background(), e.user.ID)
	if got := storedScope(t, e, list[0].Scope); !reflect.DeepEqual(got, tools.Scope{"srv": tools.ServerRows{"database_id": {"5"}}}) {
		t.Errorf("stored scope %s", list[0].Scope)
	}
	_, edit := e.get(t, "/tokens/"+list[0].ID+"/edit", true)
	for _, want := range []string{`<option value="database_id" selected>`, `>5</textarea>`, "limited: database_id", "not limited by scope"} {
		if !strings.Contains(edit, want) {
			t.Errorf("edit page misses %q", want)
		}
	}
}

func TestTokenFormRefusesForeignServer(t *testing.T) {
	e := newEnv(t)
	scopedServer(t, e)
	_, bobCookie := e.sessionFor(t, "bob@example.com")
	f := newMCPFake(t, &mcpFake{})
	f.set(tool("x", "X.", true))
	e.do(t, "POST", "/upstreams", url.Values{"name": {"other"}, "url": {f.URL}, "auth": {"none"}}, bobCookie)
	form := url.Values{"name": {"bot"}, "expiry": {"30"}, "tools": {"srv__q"}, "arg.other": {"x"}, "vals.other": {"1"}}
	if code, body := e.post(t, "/tokens", form, e.url); code != 400 || !strings.Contains(body, "Unknown server other.") {
		t.Errorf("foreign server: %d\n%s", code, body)
	}
}

func TestEditShowsStaleRow(t *testing.T) {
	e := newEnv(t)
	scopedServer(t, e)
	if _, err := e.as.CreatePersonalToken(context.Background(), e.user.ID, auth.NewToken{Name: "bot", Tools: []string{"srv__q"}, Scope: []byte(`{"srv":{"gone":["1"]}}`), TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	list, _ := e.as.Store.ListPersonalTokens(context.Background(), e.user.ID)
	_, edit := e.get(t, "/tokens/"+list[0].ID+"/edit", true)
	if !strings.Contains(edit, `<option value="gone" selected>`) || !strings.Contains(edit, `class="stale"`) {
		t.Errorf("stale row not flagged:\n%s", edit)
	}
}

func TestOldScopeStillEdits(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.as.CreatePersonalToken(ctx, e.user.ID, auth.NewToken{Name: "old", Tools: []string{"loki_query"}, Scope: []byte(`{"fake":["a","b"]}`), TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	list, _ := e.as.Store.ListPersonalTokens(ctx, e.user.ID)
	_, edit := e.get(t, "/tokens/"+list[0].ID+"/edit", true)
	if !strings.Contains(edit, "a\nb</textarea>") {
		t.Fatalf("saved values missing:\n%s", edit)
	}
	if code, _ := e.post(t, "/tokens/"+list[0].ID, url.Values{"name": {"old"}, "tools": {"loki_query"}, "scope.fake": {"a\nb"}}, e.url); code != 303 {
		t.Fatalf("save: %d", code)
	}
	list, _ = e.as.Store.ListPersonalTokens(ctx, e.user.ID)
	if got := storedScope(t, e, list[0].Scope); !reflect.DeepEqual(got, tools.Scope{"fake": []string{"a", "b"}}) {
		t.Errorf("scope after save: %s", list[0].Scope)
	}
}
