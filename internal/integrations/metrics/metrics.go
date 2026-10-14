// Package metrics exposes a PromQL query tool against a Prometheus-compatible API.
package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/upstream"
)

type Metrics struct {
	base   string
	client *http.Client
}

func New(baseURL string, insecure bool) *Metrics {
	return &Metrics{base: strings.TrimRight(baseURL, "/"), client: upstream.Client(insecure)}
}

func (m *Metrics) System() string { return "metrics" }
func (m *Metrics) Title() string  { return "Metrics" }

func (m *Metrics) Fields() []tools.Field {
	return []tools.Field{
		{Name: "token", Label: "Token (or leave empty and use username + password)", Secret: true, Optional: true},
		{Name: "username", Label: "Username", Optional: true},
		{Name: "password", Label: "Password", Secret: true, Optional: true},
	}
}

func (m *Metrics) Help() []string {
	g := upstream.Origin(m.base)
	return []string{
		"These metrics (Prometheus) are read through Grafana at " + g + ".",
		"Easiest: leave the token empty and enter the username and password you use to sign in to " + g + ".",
		"Or paste a Grafana service account token (Grafana: Administration, Users and access, Service accounts, Add token) with the Viewer role.",
	}
}
func (m *Metrics) Validate(ctx context.Context, c tools.Creds) error {
	_, err := m.get(ctx, c, "/api/v1/status/buildinfo", nil)
	return err
}

func (m *Metrics) get(ctx context.Context, c tools.Creds, path string, q url.Values) ([]byte, error) {
	u := m.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	upstream.SetAuth(req, c)
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	return b, upstream.StatusErr("prometheus", resp.StatusCode, b)
}

type queryArgs struct {
	Query string `json:"query"`
	Start string `json:"start"`
	End   string `json:"end"`
	Step  string `json:"step"`
}

// query runs an instant query, or a range query when Start is set
// (End defaults to now, Step to about 60 points across the range).
func (m *Metrics) query(ctx context.Context, c tools.Creds, a queryArgs) (string, error) {
	q := strings.TrimSpace(a.Query)
	if q == "" {
		return "", errors.New("empty PromQL query")
	}
	params := url.Values{"query": {q}}
	path := "/api/v1/query"
	if start, ok := upstream.ParseTime(a.Start); ok {
		end := time.Now()
		if e, ok := upstream.ParseTime(a.End); ok {
			end = e
		}
		if end.Before(start) {
			start, end = end, start
		}
		step := strings.TrimSpace(a.Step)
		if step == "" {
			step = defaultStep(end.Sub(start))
		}
		path = "/api/v1/query_range"
		params.Set("start", strconv.FormatInt(start.Unix(), 10))
		params.Set("end", strconv.FormatInt(end.Unix(), 10))
		params.Set("step", step)
	}
	b, err := m.get(ctx, c, path, params)
	if err != nil {
		return "", err
	}
	typ, lines, err := parse(b)
	if err != nil {
		return "", err
	}
	if len(lines) == 0 {
		return "(no series matched)", nil
	}
	return fmt.Sprintf("%s (%d series):\n%s", typ, len(lines), strings.Join(lines, "\n")), nil
}

func defaultStep(d time.Duration) string {
	step := d / 60
	if step < 15*time.Second {
		step = 15 * time.Second
	}
	return strconv.Itoa(int(step.Round(time.Second).Seconds())) + "s"
}

// parse flattens a Prometheus API response into one line per series.
func parse(body []byte) (string, []string, error) {
	var r struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			ResultType string          `json:"resultType"`
			Result     json.RawMessage `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", nil, fmt.Errorf("prometheus: parse: %w", err)
	}
	if r.Status != "success" {
		return "", nil, errors.New("prometheus: " + r.Error)
	}
	var lines []string
	switch r.Data.ResultType {
	case "vector":
		var series []struct {
			Metric map[string]string `json:"metric"`
			Value  [2]any            `json:"value"`
		}
		if err := json.Unmarshal(r.Data.Result, &series); err != nil {
			return "", nil, fmt.Errorf("prometheus: parse vector: %w", err)
		}
		for _, s := range series {
			lines = append(lines, labels(s.Metric)+" => "+valStr(s.Value[1]))
		}
	case "matrix":
		var series []struct {
			Metric map[string]string `json:"metric"`
			Values [][2]any          `json:"values"`
		}
		if err := json.Unmarshal(r.Data.Result, &series); err != nil {
			return "", nil, fmt.Errorf("prometheus: parse matrix: %w", err)
		}
		for _, s := range series {
			lines = append(lines, labels(s.Metric)+" => "+rangeSummary(s.Values))
		}
	case "scalar":
		var v [2]any
		if err := json.Unmarshal(r.Data.Result, &v); err != nil {
			return "", nil, fmt.Errorf("prometheus: parse scalar: %w", err)
		}
		lines = append(lines, valStr(v[1]))
	default:
		return "", nil, errors.New("prometheus: unsupported resultType " + r.Data.ResultType)
	}
	return r.Data.ResultType, lines, nil
}

// labels renders name{k=v,...} with __name__ in front and the rest sorted.
func labels(m map[string]string) string {
	name := m["__name__"]
	var parts []string
	for k, v := range m {
		if k != "__name__" {
			parts = append(parts, k+"="+v)
		}
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		if name == "" {
			return "{}"
		}
		return name
	}
	return name + "{" + strings.Join(parts, ",") + "}"
}

// rangeSummary compresses a matrix series into first/min/max/last.
func rangeSummary(values [][2]any) string {
	if len(values) == 0 {
		return "(no points)"
	}
	var first, last, lo, hi float64
	seen := false
	for _, v := range values {
		f, err := strconv.ParseFloat(fmt.Sprint(v[1]), 64)
		if err != nil {
			continue
		}
		if !seen {
			first, lo, hi, seen = f, f, f, true
		}
		lo, hi, last = min(lo, f), max(hi, f), f
	}
	return fmt.Sprintf("first=%s min=%s max=%s last=%s (%d points)", fmtFloat(first), fmtFloat(lo), fmtFloat(hi), fmtFloat(last), len(values))
}

func valStr(v any) string {
	if s, ok := v.(string); ok {
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return fmtFloat(f)
		}
		return s
	}
	return fmt.Sprint(v)
}

func fmtFloat(f float64) string {
	if f == float64(int64(f)) && f < 1e15 {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', 6, 64)
}

func (m *Metrics) Tools() []tools.Tool {
	return []tools.Tool{{
		Name: "metrics_query",
		Description: "Run PromQL against Prometheus (e.g. pod/container CPU, memory, restarts). Instant query by default; " +
			"set start (+optional end/step) for a range with first/min/max/last per series, ideal for before/after-deploy comparisons. " +
			"cadvisor series need container!=\"\" to skip pod-sandbox rows; rate() windows should be >= 2m. Times without an offset are server local time (TZ).",
		Schema: tools.Object(map[string]any{
			"query": tools.Str("PromQL query"),
			"start": tools.Str("optional range start: 'YYYY-MM-DD HH:MM' (server local time, TZ) or RFC3339; omit for an instant query"),
			"end":   tools.Str("optional range end (defaults to now)"),
			"step":  tools.Str("optional range step like '1m' (default about 60 points)"),
		}, "query"),
		Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
			var a queryArgs
			if err := tools.Args(raw, &a); err != nil {
				return "", err
			}
			return m.query(ctx, c, a)
		},
	}}
}
