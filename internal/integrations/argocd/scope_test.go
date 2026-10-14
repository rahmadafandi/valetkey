package argocd

import (
	"encoding/json"
	"testing"

	"github.com/rahmadafandi/valetkey/internal/tools"
)

func TestScope(t *testing.T) {
	a := &ArgoCD{}
	scope, err := a.ParseScope(json.RawMessage(`["web","api"]`))
	if err != nil {
		t.Fatal(err)
	}
	for args, ok := range map[string]bool{
		`{"app":"web"}`:  true,
		`{"app":"api"}`:  true,
		`{"app":"db"}`:   false,
		`{"app":" web"}`: false,
		`{"app":""}`:     false,
		`{}`:             false,
		``:               false,
	} {
		err := a.CheckScope(scope, "argocd_sync", json.RawMessage(args))
		if (err == nil) != ok {
			t.Errorf("%s: err = %v, want ok=%v", args, err, ok)
		}
		if err != nil && !tools.IsRefusal(err) {
			t.Errorf("%s: not a refusal: %v", args, err)
		}
	}
	for _, bad := range []string{`3`, `[""]`, `[]`, `null`} {
		if _, err := a.ParseScope(json.RawMessage(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
