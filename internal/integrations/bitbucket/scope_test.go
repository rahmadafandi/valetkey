package bitbucket

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/rahmadafandi/valetkey/internal/tools"
)

func TestParseScope(t *testing.T) {
	b := &Bitbucket{}
	if v, err := b.ParseScope(json.RawMessage(`" acme/web "`)); err != nil || !slices.Equal(v.([]string), []string{"acme/web"}) {
		t.Errorf("repo: %v %v", v, err)
	}
	if v, err := b.ParseScope(json.RawMessage(`["acme/web","acme/api"]`)); err != nil || !slices.Equal(v.([]string), []string{"acme/web", "acme/api"}) {
		t.Errorf("list: %v %v", v, err)
	}
	for _, bad := range []string{`3`, `""`, `null`, `[]`, `"acme"`, `"acme/web/x"`, `["acme/web",""]`, `["acme/web","acme"]`, `"acme/*"`} {
		if _, err := b.ParseScope(json.RawMessage(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestCheckScope(t *testing.T) {
	b := &Bitbucket{}
	scope, err := b.ParseScope(json.RawMessage(`["acme/web","acme/api"]`))
	if err != nil {
		t.Fatal(err)
	}
	for args, ok := range map[string]bool{
		`{"repo":"acme/web"}`:   true,
		`{"repo":"acme/api"}`:   true,
		`{"repo":"acme/other"}`: false,
		`{"repo":"acme/web/"}`:  false,
		`{}`:                    false,
		``:                      false,
	} {
		err := b.CheckScope(scope, "bitbucket_pr_merge", json.RawMessage(args))
		if (err == nil) != ok {
			t.Errorf("%s: err = %v, want ok=%v", args, err, ok)
		}
		if err != nil && !tools.IsRefusal(err) {
			t.Errorf("%s: not a refusal: %v", args, err)
		}
	}
}
