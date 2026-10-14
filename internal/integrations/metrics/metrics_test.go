package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/upstream"
)

var (
	ctx   = context.Background()
	creds = tools.Creds{"token": "tok"}
)

func setup(t *testing.T) (*Metrics, *string) {
	var path string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		path = r.URL.Path + "?step=" + r.URL.Query().Get("step")
		switch {
		case r.URL.Path == "/api/v1/status/buildinfo":
			w.Write([]byte(`{"status":"success","data":{"version":"2.53.0"}}`))
		case r.URL.Query().Get("query") == "bad(":
			w.Write([]byte(`{"status":"error","error":"parse error"}`))
		case r.URL.Path == "/api/v1/query_range":
			w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[
				{"metric":{"__name__":"cpu","pod":"web-1"},"values":[[1,"1"],[2,"3"],[3,"2"]]}]}}`))
		default:
			w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
				{"metric":{"__name__":"container_memory","pod":"web-1","namespace":"production"},"value":[1,"1024"]}]}}`))
		}
	}))
	t.Cleanup(ts.Close)
	return New(ts.URL, false), &path
}

func query(t *testing.T, m *Metrics, c tools.Creds, args string) (string, error) {
	t.Helper()
	return m.Tools()[0].Run(ctx, c, json.RawMessage(args))
}

func TestInstant(t *testing.T) {
	m, path := setup(t)
	out, err := query(t, m, creds, `{"query":"container_memory"}`)
	if err != nil || out != "vector (1 series):\ncontainer_memory{namespace=production,pod=web-1} => 1024" {
		t.Errorf("out=%q err=%v", out, err)
	}
	if !strings.HasPrefix(*path, "/api/v1/query?") {
		t.Errorf("path = %s", *path)
	}
}

func TestRange(t *testing.T) {
	m, path := setup(t)
	out, err := query(t, m, creds, `{"query":"cpu","start":"2026-10-14T00:00:00Z","end":"2026-10-14T01:00:00Z"}`)
	if err != nil || !strings.Contains(out, "cpu{pod=web-1} => first=1 min=1 max=3 last=2 (3 points)") {
		t.Errorf("out=%q err=%v", out, err)
	}
	if *path != "/api/v1/query_range?step=60s" {
		t.Errorf("path = %s", *path)
	}
}

func TestErrors(t *testing.T) {
	m, _ := setup(t)
	if _, err := query(t, m, creds, `{"query":"bad("}`); err == nil || !strings.Contains(err.Error(), "parse error") {
		t.Errorf("prometheus error: %v", err)
	}
	if _, err := query(t, m, tools.Creds{"token": "x"}, `{"query":"up"}`); !errors.Is(err, upstream.ErrUnauthorized) {
		t.Errorf("wrong token: %v", err)
	}
	if _, err := query(t, m, creds, `{"query":""}`); err == nil {
		t.Error("empty query accepted")
	}
	if err := m.Validate(ctx, creds); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestHelpFollowsTheURL(t *testing.T) {
	grafana := strings.Join(New("https://grafana.example.com/api/datasources/proxy/3", false).Help(), " ")
	for _, want := range []string{"through Grafana at https://grafana.example.com", "Viewer role"} {
		if !strings.Contains(grafana, want) {
			t.Errorf("Grafana URL: help misses %q: %s", want, grafana)
		}
	}
	direct := strings.Join(New("https://prometheus.example.com", false).Help(), " ")
	for _, want := range []string{"talks to the Prometheus-compatible API at https://prometheus.example.com directly", "gateway"} {
		if !strings.Contains(direct, want) {
			t.Errorf("direct URL: help misses %q: %s", want, direct)
		}
	}
	if strings.Contains(direct, "Viewer role") || strings.Contains(direct, "service account") {
		t.Errorf("direct URL: help still talks about Grafana accounts: %s", direct)
	}
}
