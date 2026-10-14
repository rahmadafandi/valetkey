package tools

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseScope(t *testing.T) {
	s, err := ParseScope([]byte(`{"bitbucket":"acme/web","jenkins":"deploy-web","loki":"{app=\"web\"}"}`))
	if err != nil || s.Bitbucket != "acme/web" || len(s.Jenkins) != 1 || s.Jenkins[0] != "deploy-web" {
		t.Fatalf("%+v %v", s, err)
	}
	if s, err := ParseScope([]byte(`{"jenkins":["a","b/c"]}`)); err != nil || len(s.Jenkins) != 2 {
		t.Errorf("list: %+v %v", s, err)
	}
	if s, err := ParseScope(nil); err != nil || s.Bitbucket != "" {
		t.Errorf("empty: %+v %v", s, err)
	}
	for _, bad := range []string{`{"jenkin":"x"}`, `{"jenkins":3}`, `{"jenkins":[""]}`, `{"loki":"{a=\"b\"} or {c=\"d\"}"}`, `{"loki":"job"}`, `[]`} {
		if _, err := ParseScope([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestScopeCheck(t *testing.T) {
	s := Scope{Bitbucket: "acme/web", Jenkins: []string{"deploy-web", "folder/deep job"}, Loki: `{app="web"}`}
	args := func(v map[string]any) json.RawMessage { b, _ := json.Marshal(v); return b }
	cases := []struct {
		tool string
		args map[string]any
		ok   bool
	}{
		{"ops_status", nil, true},
		{"bitbucket_pr_merge", map[string]any{"repo": "acme/web"}, true},
		{"bitbucket_pr_merge", map[string]any{"repo": "acme/other"}, false},
		{"bitbucket_pr_merge", nil, false},
		{"jenkins_deploy", map[string]any{"jobURL": "https://jenkins.example.com/job/deploy-web/"}, true},
		{"jenkins_deploy", map[string]any{"jobURL": "https://jenkins.example.com/job/folder/job/deep%20job"}, true},
		{"jenkins_deploy", map[string]any{"jobURL": "https://jenkins.example.com/job/deploy-web-canary/"}, false},
		{"jenkins_deploy", map[string]any{"jobURL": "https://jenkins.example.com/"}, false},
		{"loki_query", map[string]any{"query": `{ app = "web" } |= "error {x}"`}, true},
		{"loki_query", map[string]any{"query": `sum(rate({app="web"}[5m])) / sum(rate({app="other"}[5m]))`}, false},
		{"loki_query", map[string]any{"query": `{app="other"}`}, false},
		{"loki_query", map[string]any{"query": `|= "x"`}, false},
		{"metrics_query", map[string]any{"query": "up"}, false},
		{"argocd_sync", map[string]any{"app": "web"}, false},
	}
	for _, c := range cases {
		err := s.Check(c.tool, args(c.args))
		if (err == nil) != c.ok {
			t.Errorf("%s %v: err = %v, want ok=%v", c.tool, c.args, err, c.ok)
		}
		if err != nil && !strings.HasPrefix(err.Error(), "refused: ") {
			t.Errorf("error should start with refused: %v", err)
		}
	}
	if err := (Scope{}).Check("bitbucket_pr_get", args(map[string]any{"repo": "acme/web"})); err == nil {
		t.Error("a family without a key was allowed")
	}
}
