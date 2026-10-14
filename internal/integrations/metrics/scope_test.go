package metrics

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rahmadafandi/valetkey/internal/tools"
)

func TestParseScope(t *testing.T) {
	m := &Metrics{}
	if _, err := m.ParseScope(json.RawMessage(`"{namespace=\"web\", team=\"ops\"}"`)); err != nil {
		t.Errorf("selector: %v", err)
	}
	for _, bad := range []string{`3`, `""`, `null`, `"{}"`, `"{namespace=~\"w.*\"}"`, `"{namespace!=\"db\"}"`, `"up{namespace=\"web\"}"`, `"{namespace=\"\"}"`, `"{namespace=\"web\""`, `"{namespace=\"web\",namespace=\"db\"}"`} {
		if _, err := m.ParseScope(json.RawMessage(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestParseScopeNullMessage(t *testing.T) {
	_, err := (&Metrics{}).ParseScope(json.RawMessage(`null`))
	if err == nil || !strings.Contains(err.Error(), "expected one selector string") {
		t.Errorf("null: %v", err)
	}
}

func TestCheckScope(t *testing.T) {
	m := &Metrics{}
	scope, err := m.ParseScope(json.RawMessage(`"{namespace=\"web\"}"`))
	if err != nil {
		t.Fatal(err)
	}
	for query, ok := range map[string]bool{
		`up{namespace="web"}`: true,
		`sum(rate(http_requests_total{namespace="web",code="500"}[5m]))`: true,
		`vector(1)`:                                 true,
		`{__name__=~".+", namespace="web"}`:         true,
		`max_over_time(up{namespace="web"}[1h:5m])`: true,
		`sum(up)`:              false,
		`up`:                   false,
		`up{namespace=~"web"}`: false,
		`up{namespace="web"} or up{namespace="db"}`:  false,
		`rate(x{namespace="web"}[5m]) / rate(x[5m])`: false,
		`max_over_time(up[1h:5m])`:                   false,
		`up{namespace="web" or namespace="db"}`:      false,
		"up{namespace=\"web\"} # comment\n+ up":      false,
		`up{`:                                        false,
		``:                                           false,
	} {
		args, _ := json.Marshal(map[string]string{"query": query})
		err := m.CheckScope(scope, "metrics_query", args)
		if (err == nil) != ok {
			t.Errorf("%s: err = %v, want ok=%v", query, err, ok)
		}
		if err != nil && !tools.IsRefusal(err) {
			t.Errorf("%s: not a refusal: %v", query, err)
		}
	}
}
