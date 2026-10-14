// Package loki exposes a LogQL query tool.
package loki

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

type Loki struct {
	base   string
	client *http.Client
}

func New(baseURL string, insecure bool) *Loki {
	return &Loki{base: strings.TrimRight(baseURL, "/"), client: upstream.Client(insecure)}
}

func (l *Loki) System() string { return "loki" }
func (l *Loki) Title() string  { return "Loki" }

func (l *Loki) Fields() []tools.Field {
	return []tools.Field{
		{Name: "token", Label: "Token (or leave empty and use username + password)", Secret: true, Optional: true},
		{Name: "username", Label: "Username", Optional: true},
		{Name: "password", Label: "Password", Secret: true, Optional: true},
	}
}

func (l *Loki) Help() []string {
	g := upstream.Origin(l.base)
	return []string{
		"These logs (Loki) are read through Grafana at " + g + ".",
		"Easiest: leave the token empty and enter the username and password you use to sign in to " + g + ".",
		"Or paste a Grafana service account token (Grafana: Administration, Users and access, Service accounts, Add token) with the Viewer role.",
	}
}
func (l *Loki) Validate(ctx context.Context, c tools.Creds) error {
	_, err := l.get(ctx, c, "/loki/api/v1/labels", nil)
	return err
}

func (l *Loki) get(ctx context.Context, c tools.Creds, path string, q url.Values) ([]byte, error) {
	u := l.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	upstream.SetAuth(req, c)
	resp, err := l.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	return b, upstream.StatusErr("loki", resp.StatusCode, b)
}

type queryArgs struct {
	Query        string `json:"query"`
	SinceMinutes int    `json:"sinceMinutes"`
	Start        string `json:"start"`
	End          string `json:"end"`
	Limit        int    `json:"limit"`
}

func (l *Loki) query(ctx context.Context, c tools.Creds, a queryArgs) (string, error) {
	if strings.TrimSpace(a.Query) == "" {
		return "", errors.New("empty LogQL query")
	}
	limit := a.Limit
	if limit <= 0 {
		limit = 500
	} else if limit > 5000 {
		limit = 5000
	}
	var start, end time.Time
	if s, ok := upstream.ParseTime(a.Start); ok {
		start, end = s, time.Now()
		if e, ok := upstream.ParseTime(a.End); ok {
			end = e
		}
		if end.Before(start) {
			start, end = end, start
		}
	} else {
		since := a.SinceMinutes
		if since <= 0 {
			since = 60
		}
		end = time.Now()
		start = end.Add(-time.Duration(since) * time.Minute)
	}
	q := url.Values{}
	q.Set("query", a.Query)
	q.Set("start", strconv.FormatInt(start.UnixNano(), 10))
	q.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	q.Set("limit", strconv.Itoa(limit))
	q.Set("direction", "backward")
	b, err := l.get(ctx, c, "/loki/api/v1/query_range", q)
	if err != nil {
		return "", err
	}
	lines, err := parseLines(b, limit)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d lines (newest first):\n%s", len(lines), strings.Join(lines, "\n")), nil
}

// parseLines flattens Loki's streams into timestamp-prefixed lines, newest first, capped at limit.
func parseLines(body []byte, limit int) ([]string, error) {
	var r struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Values [][2]string `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil || (r.Status != "" && r.Status != "success") {
		return nil, fmt.Errorf("loki: unexpected response: %s", truncateBytes(body, 200))
	}
	type entry struct {
		ts   int64
		line string
	}
	var all []entry
	for _, s := range r.Data.Result {
		for _, v := range s.Values {
			ns, _ := strconv.ParseInt(v[0], 10, 64)
			all = append(all, entry{ns, v[1]})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ts > all[j].ts })
	if len(all) > limit {
		all = all[:limit]
	}
	out := make([]string, 0, len(all))
	for _, e := range all {
		out = append(out, time.Unix(0, e.ts).Format("2006-01-02 15:04:05")+"  "+e.line)
	}
	return out, nil
}

func truncateBytes(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}

func (l *Loki) Tools() []tools.Tool {
	return []tools.Tool{{
		Name: "loki_query",
		Description: "Query Loki logs with LogQL (read-only). Narrow with line filters: |= contains, != not-contains, |~ regex, !~ not-regex. " +
			"Use sinceMinutes for a relative window, or start (+optional end) for a specific past window. " +
			"Times without an offset are server local time (TZ). Example: {app=\"web\"} |= \"error\"",
		Schema: tools.Object(map[string]any{
			"query":        tools.Str("LogQL query, including any line filters"),
			"sinceMinutes": tools.Int("look-back window in minutes from now (default 60; ignored when start is set)"),
			"start":        tools.Str("absolute range start: 'YYYY-MM-DD HH:MM' (server local time, TZ) or RFC3339"),
			"end":          tools.Str("absolute range end (defaults to now when start is set)"),
			"limit":        tools.Int("max lines (default 500, max 5000)"),
		}, "query"),
		Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
			var a queryArgs
			if err := tools.Args(raw, &a); err != nil {
				return "", err
			}
			return l.query(ctx, c, a)
		},
	}}
}
