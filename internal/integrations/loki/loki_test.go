package loki

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/upstream"
)

var (
	ctx   = context.Background()
	creds = tools.Creds{"username": "alice", "password": "pw"}
)

// Two streams, interleaved timestamps (ns): 1000, 3000 and 2000.
const result = `{"data":{"result":[
 {"values":[["1000000000000","first"],["3000000000000","third"]]},
 {"values":[["2000000000000","second"]]}]}}`

func setup(t *testing.T) (*Loki, *url.Values) {
	var got url.Values
	mux := http.NewServeMux()
	mux.HandleFunc("GET /loki/api/v1/query_range", func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "alice" || p != "pw" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		got = r.URL.Query()
		w.Write([]byte(result))
	})
	mux.HandleFunc("GET /loki/api/v1/labels", func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); !ok {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"status":"success","data":["job"]}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return New(ts.URL, false), &got
}

func query(t *testing.T, l *Loki, c tools.Creds, args string) (string, error) {
	t.Helper()
	return l.Tools()[0].Run(ctx, c, json.RawMessage(args))
}

func TestNewestFirstAndLimit(t *testing.T) {
	l, got := setup(t)
	out, err := query(t, l, creds, `{"query":"{job=\"web\"} |= \"error\"","limit":2}`)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(out, "\n")
	if lines[0] != "2 lines (newest first):" || !strings.HasSuffix(lines[1], "third") || !strings.HasSuffix(lines[2], "second") || len(lines) != 3 {
		t.Errorf("out = %q", out)
	}
	if got.Get("direction") != "backward" || got.Get("limit") != "2" || got.Get("query") != `{job="web"} |= "error"` {
		t.Errorf("params = %v", *got)
	}
}

func TestRelativeWindowDefault(t *testing.T) {
	l, got := setup(t)
	if _, err := query(t, l, creds, `{"query":"{job=\"web\"}"}`); err != nil {
		t.Fatal(err)
	}
	start, _ := strconv.ParseInt(got.Get("start"), 10, 64)
	end, _ := strconv.ParseInt(got.Get("end"), 10, 64)
	if d := time.Duration(end - start); d != time.Hour {
		t.Errorf("window = %v, want 1h", d)
	}
	if got.Get("limit") != "500" {
		t.Errorf("limit = %s", got.Get("limit"))
	}
}

func TestAbsoluteRangeInLocalTime(t *testing.T) {
	zone := time.FixedZone("UTC+7", 7*60*60)
	old := time.Local
	time.Local = zone
	defer func() { time.Local = old }()

	l, got := setup(t)
	// end before start: the range is swapped, not rejected.
	if _, err := query(t, l, creds, `{"query":"{job=\"web\"}","start":"2026-10-14 11:00","end":"2026-10-14 10:00"}`); err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 10, 14, 3, 0, 0, 0, time.UTC).UnixNano()
	if got.Get("start") != strconv.FormatInt(want, 10) {
		t.Errorf("start = %s, want %d (10:00 UTC+7)", got.Get("start"), want)
	}
}

func TestErrors(t *testing.T) {
	l, _ := setup(t)
	if _, err := query(t, l, creds, `{"query":"  "}`); err == nil {
		t.Error("empty query accepted")
	}
	if _, err := query(t, l, tools.Creds{"username": "bob", "password": "x"}, `{"query":"{job=\"web\"}"}`); !errors.Is(err, upstream.ErrUnauthorized) {
		t.Errorf("wrong creds: %v", err)
	}
	if err := l.Validate(ctx, creds); err != nil {
		t.Errorf("Validate: %v", err)
	}
	if err := l.Validate(ctx, tools.Creds{}); !errors.Is(err, upstream.ErrUnauthorized) {
		t.Errorf("Validate without creds: %v", err)
	}
}

func TestNonLokiBodyIsAnError(t *testing.T) {
	for _, body := range []string{"<html>login</html>", `{"status":"error","error":"boom"}`} {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(body)) }))
		out, err := query(t, New(ts.URL, false), creds, `{"query":"{a=\"b\"}"}`)
		ts.Close()
		if err == nil || !strings.Contains(err.Error(), "loki: unexpected response") || strings.Contains(out, "0 lines") {
			t.Errorf("%q: out=%q err=%v", body, out, err)
		}
	}
}
