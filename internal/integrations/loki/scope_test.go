package loki

import (
	"encoding/json"
	"testing"

	"github.com/rahmadafandi/valetkey/internal/tools"
)

func TestParseScope(t *testing.T) {
	l := &Loki{}
	if v, err := l.ParseScope(json.RawMessage(`" { app = \"web\" } "`)); err != nil || v != `{app="web"}` {
		t.Errorf("selector: %v %v", v, err)
	}
	for _, bad := range []string{`3`, `""`, `null`, `"job"`, `"{a=\"b\"} or {c=\"d\"}"`, `"{a=\"b\"} |= \"x\""`, `"{a=\"b\""`, `["{a=\"b\"}"]`} {
		if _, err := l.ParseScope(json.RawMessage(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestCheckScope(t *testing.T) {
	l := &Loki{}
	scope, err := l.ParseScope(json.RawMessage(`"{app=\"web\"}"`))
	if err != nil {
		t.Fatal(err)
	}
	for query, ok := range map[string]bool{
		`{ app = "web" } |= "error {x}"`: true,
		"{app=\"web\"} |~ `{.*}`":        true,
		`sum(rate({app="web"}[5m]))`:     true,
		`sum by ('"') (count_over_time({app=~".+"}[5m])) + sum by ('"') (count_over_time({app="web"}[5m]))`: false,
		`{app="web"} # x`:                 false,
		`{app="web"} |= 'x'`:              false,
		`{app="web"} \ "x"`:               false,
		`{app="web"} |= "x" ; {app="db"}`: false,
		"{app=\"web\"} |= \"timeout\" |~ `5\\d{2}` | json | line_format \"{{.msg}}\"":                                                                        true,
		`sum by (pod) (rate({app="web"} |= "error" | json | unwrap duration_ms [5m] offset 5m)) / sum by (pod) (count_over_time({app="web"}[5m] offset 5m))`: true,
		`sum(count_over_time({app="web"} != "debug" !~ "trace|info" [1h])) > 0.5 * 2 - 1`:                                                                    true,
		`sum(rate({app="web"}[5m])) / sum(rate({app="other"}[5m]))`:                                                                                          false,
		`{app="other"}`:          false,
		`{app="web",env="prod"}`: false,
		`{app=~"web|db"}`:        false,
		`|= "x"`:                 false,
		`{app="web"`:             false,
		`{app="web"} |= "x`:      false,
		``:                       false,
		"sum(count_over_time({app=\"web\"}[5m])) /* ` */ + sum(count_over_time({app=~\".+\"}[5m])) /* ` */": false,
		"sum(count_over_time({app=\"web\"}[5m])) // `\n + sum(count_over_time({app=~\".+\"}[5m])) // `":     false,
		`sum(count_over_time({app="web"}[5m])) / sum(count_over_time({app="web"} |= "a//b" [5m]))`:          true,
		"sum(rate({app=\"web\"}[5m])) # \"\n + sum(rate({app=~\".+\"}[5m])) #\"":                            false,
	} {
		args, _ := json.Marshal(map[string]string{"query": query})
		err := l.CheckScope(scope, "loki_query", args)
		if (err == nil) != ok {
			t.Errorf("%s: err = %v, want ok=%v", query, err, ok)
		}
		if err != nil && !tools.IsRefusal(err) {
			t.Errorf("%s: not a refusal: %v", query, err)
		}
	}
}
