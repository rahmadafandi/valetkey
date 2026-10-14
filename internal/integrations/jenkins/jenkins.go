// Package jenkins exposes Jenkins job and build tools, authenticated per user.
package jenkins

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/upstream"
)

type Jenkins struct {
	base   *url.URL
	client *http.Client
}

func New(baseURL string, insecure bool) (*Jenkins, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("jenkins: invalid base URL %q", baseURL)
	}
	return &Jenkins{base: u, client: upstream.Client(insecure)}, nil
}

func (j *Jenkins) System() string { return "jenkins" }
func (j *Jenkins) Title() string  { return "Jenkins" }

func (j *Jenkins) Fields() []tools.Field {
	return []tools.Field{
		{Name: "username", Label: "Username"},
		{Name: "token", Label: "API token", Secret: true},
	}
}

func (j *Jenkins) Help() []string {
	return []string{
		"Sign in to " + j.base.String() + ", click your name (top right) and open Security (older Jenkins: Configure).",
		"Under API Token, click Add new Token, name it \"valetkey\", then Generate and copy the token. Jenkins shows it only once.",
		"Username is your Jenkins user ID: the last part of the URL of your profile page (" + j.base.String() + "/me), usually your LDAP name.",
	}
}
func (j *Jenkins) Validate(ctx context.Context, c tools.Creds) error {
	_, err := j.do(ctx, c, http.MethodGet, j.base.String()+"/me/api/json", nil, nil, 64<<10)
	return err
}

// jobURL normalizes a job URL and refuses anything outside the configured
// Jenkins, so a user's credentials are never sent to another host.
func (j *Jenkins) jobURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid job URL: %w", err)
	}
	path := strings.TrimRight(u.Path, "/")
	if u.Scheme != j.base.Scheme || u.Host != j.base.Host || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		!strings.HasPrefix(path+"/", j.base.Path+"/") || path == j.base.Path {
		return "", fmt.Errorf("refused: job URL must be a job under %s", j.base)
	}
	return u.Scheme + "://" + u.Host + path, nil
}

func (j *Jenkins) do(ctx context.Context, c tools.Creds, method, u string, body io.Reader, header http.Header, limit int64) ([]byte, error) {
	b, _, err := j.doHeader(ctx, c, method, u, body, header, limit)
	return b, err
}

// doHeader is do that also returns the response headers.
func (j *Jenkins) doHeader(ctx context.Context, c tools.Creds, method, u string, body io.Reader, header http.Header, limit int64) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, nil, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.SetBasicAuth(c["username"], c["token"])
	resp, err := j.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, nil, err
	}
	return b, resp.Header, upstream.StatusErr("jenkins", resp.StatusCode, b)
}

// crumb fetches a CSRF crumb header. Jenkins without CSRF protection answers
// 404 here and needs none.
func (j *Jenkins) crumb(ctx context.Context, c tools.Creds) (http.Header, error) {
	h := http.Header{}
	b, err := j.do(ctx, c, http.MethodGet, j.base.String()+"/crumbIssuer/api/json", nil, nil, 4096)
	if errors.Is(err, upstream.ErrUnauthorized) {
		return nil, err
	}
	var cr struct {
		Field string `json:"crumbRequestField"`
		Crumb string `json:"crumb"`
	}
	if err == nil && json.Unmarshal(b, &cr) == nil && cr.Field != "" {
		h.Set(cr.Field, cr.Crumb)
	}
	return h, nil
}

func (j *Jenkins) jobParams(ctx context.Context, c tools.Creds, raw string) (string, error) {
	u, err := j.jobURL(raw)
	if err != nil {
		return "", err
	}
	b, err := j.do(ctx, c, http.MethodGet,
		u+"/api/json?tree=property[parameterDefinitions[name,type,description,choices,defaultParameterValue[value]]]", nil, nil, 256<<10)
	if err != nil {
		return "", err
	}
	var jr struct {
		Property []struct {
			ParameterDefinitions []struct {
				Name                  string   `json:"name"`
				Type                  string   `json:"type"`
				Choices               []string `json:"choices"`
				DefaultParameterValue struct {
					Value any `json:"value"`
				} `json:"defaultParameterValue"`
			} `json:"parameterDefinitions"`
		} `json:"property"`
	}
	if err := json.Unmarshal(b, &jr); err != nil {
		return "", fmt.Errorf("jenkins: parse job: %w", err)
	}
	var sb strings.Builder
	for _, p := range jr.Property {
		for _, d := range p.ParameterDefinitions {
			fmt.Fprintf(&sb, "  %s (%s) default=%q", d.Name, paramType(d.Type), stringify(d.DefaultParameterValue.Value))
			if len(d.Choices) > 0 {
				fmt.Fprintf(&sb, " choices=%v", d.Choices)
			}
			sb.WriteByte('\n')
		}
	}
	if sb.Len() == 0 {
		return "job has no parameters (use jenkins_deploy with no params)", nil
	}
	return "parameters:\n" + sb.String(), nil
}

func paramType(t string) string {
	switch {
	case strings.Contains(t, "Choice"):
		return "choice"
	case strings.Contains(t, "Boolean"):
		return "boolean"
	case strings.Contains(t, "Text"):
		return "text"
	case strings.Contains(t, "Password"):
		return "password"
	default:
		return "string"
	}
}

func stringify(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func (j *Jenkins) builds(ctx context.Context, c tools.Creds, raw string, limit int) (string, error) {
	u, err := j.jobURL(raw)
	if err != nil {
		return "", err
	}
	if limit <= 0 || limit > 30 {
		limit = 10
	}
	b, err := j.do(ctx, c, http.MethodGet, fmt.Sprintf(
		"%s/api/json?tree=builds[number,result,building,timestamp,displayName,description,changeSet[items[commitId,msg,author[fullName]]]]{0,%d}",
		u, limit), nil, nil, 1<<20)
	if err != nil {
		return "", err
	}
	var jr struct {
		Builds []struct {
			Number      int    `json:"number"`
			Result      string `json:"result"`
			Building    bool   `json:"building"`
			Timestamp   int64  `json:"timestamp"`
			DisplayName string `json:"displayName"`
			Description string `json:"description"`
			ChangeSet   struct {
				Items []struct {
					CommitID string `json:"commitId"`
					Msg      string `json:"msg"`
					Author   struct {
						FullName string `json:"fullName"`
					} `json:"author"`
				} `json:"items"`
			} `json:"changeSet"`
		} `json:"builds"`
	}
	if err := json.Unmarshal(b, &jr); err != nil {
		return "", fmt.Errorf("jenkins: parse builds: %w", err)
	}
	if len(jr.Builds) == 0 {
		return "no builds found", nil
	}
	var sb strings.Builder
	for _, bd := range jr.Builds {
		status := bd.Result
		if bd.Building {
			status = "BUILDING"
		}
		fmt.Fprintf(&sb, "#%d %s  %s", bd.Number, status, time.UnixMilli(bd.Timestamp).Format("2006-01-02 15:04"))
		// A custom displayName (e.g. "29-441f3f9") usually carries the deployed version; "#N" is noise.
		if bd.DisplayName != "" && bd.DisplayName != fmt.Sprintf("#%d", bd.Number) {
			fmt.Fprintf(&sb, "  (%s)", bd.DisplayName)
		}
		msg := strings.TrimSpace(bd.Description)
		if n := len(bd.ChangeSet.Items); n > 0 {
			it := bd.ChangeSet.Items[n-1] // head commit of the build
			commit := it.CommitID
			if len(commit) > 10 {
				commit = commit[:10]
			}
			fmt.Fprintf(&sb, "  %s %q", commit, it.Msg)
			if it.Author.FullName != "" {
				fmt.Fprintf(&sb, "  by %s", it.Author.FullName)
			}
		} else if msg != "" {
			fmt.Fprintf(&sb, "  %q", msg)
		}
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// build queues a build (MUTATING): buildWithParameters when params are given,
// otherwise a plain build.
func (j *Jenkins) build(ctx context.Context, c tools.Creds, raw string, params map[string]string) (string, error) {
	u, err := j.jobURL(raw)
	if err != nil {
		return "", err
	}
	hdr, err := j.crumb(ctx, c)
	if err != nil {
		return "", err
	}
	endpoint, body, kind := u+"/build", io.Reader(nil), "build"
	if len(params) > 0 {
		form := url.Values{}
		for k, v := range params {
			form.Set(k, v)
		}
		endpoint, body, kind = u+"/buildWithParameters", strings.NewReader(form.Encode()), "parameterized build"
		hdr.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	_, rh, err := j.doHeader(ctx, c, http.MethodPost, endpoint, body, hdr, 2048)
	if err != nil {
		return "", err
	}
	m := queueItemRe.FindStringSubmatch(rh.Get("Location"))
	if m == nil {
		return kind + " queued", nil
	}
	num, buildURL, err := j.waitStarted(ctx, c, m[1])
	if err != nil {
		return "", fmt.Errorf("%s queued (queue item %s), but: %w", kind, m[1], err)
	}
	if num == 0 {
		return fmt.Sprintf("%s queued (queue item %s), not started within %s; check jenkins_builds", kind, m[1], startWait), nil
	}
	return fmt.Sprintf("%s started: #%d %s", kind, num, buildURL), nil
}

var queueItemRe = regexp.MustCompile(`/queue/item/(\d+)/?$`)

var (
	startWait = 30 * time.Second
	pollEvery = 2 * time.Second
)

// waitStarted polls a queue item until it becomes a build and returns its number,
// or 0 when it has not started within startWait. The item URL is rebuilt from
// the configured base, never taken from the Location header.
func (j *Jenkins) waitStarted(ctx context.Context, c tools.Creds, item string) (int, string, error) {
	deadline := time.Now().Add(startWait)
	for {
		b, err := j.do(ctx, c, http.MethodGet, j.base.String()+"/queue/item/"+item+"/api/json?tree=cancelled,executable[number,url]", nil, nil, 64<<10)
		if err != nil {
			return 0, "", err
		}
		var q struct {
			Cancelled  bool `json:"cancelled"`
			Executable *struct {
				Number int    `json:"number"`
				URL    string `json:"url"`
			} `json:"executable"`
		}
		if err := json.Unmarshal(b, &q); err != nil {
			return 0, "", fmt.Errorf("jenkins: parse queue item: %w", err)
		}
		if q.Cancelled {
			return 0, "", errors.New("the queued build was cancelled")
		}
		if q.Executable != nil && q.Executable.Number > 0 {
			return q.Executable.Number, q.Executable.URL, nil
		}
		if time.Now().After(deadline) {
			return 0, "", nil
		}
		select {
		case <-ctx.Done():
			return 0, "", ctx.Err()
		case <-time.After(pollEvery):
		}
	}
}

const (
	maxWait   = 10 * time.Minute
	tailLines = 200
)

// waitBuild polls a build until it finishes or timeout passes, then returns its
// result (BUILDING when still running) and the console tail.
func (j *Jenkins) waitBuild(ctx context.Context, c tools.Creds, raw string, number int, timeout time.Duration) (string, error) {
	u, err := j.jobURL(raw)
	if err != nil {
		return "", err
	}
	if number <= 0 {
		return "", errors.New("number is required")
	}
	if timeout <= 0 || timeout > maxWait {
		timeout = 5 * time.Minute
	}
	build := fmt.Sprintf("%s/%d", u, number)
	deadline := time.Now().Add(timeout)
	status := "BUILDING"
	for {
		b, err := j.do(ctx, c, http.MethodGet, build+"/api/json?tree=building,result", nil, nil, 64<<10)
		if err != nil {
			return "", err
		}
		var r struct {
			Building bool    `json:"building"`
			Result   *string `json:"result"`
		}
		if err := json.Unmarshal(b, &r); err != nil {
			return "", fmt.Errorf("jenkins: parse build: %w", err)
		}
		if !r.Building && r.Result != nil {
			status = *r.Result
			break
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(pollEvery):
		}
	}
	tail, err := j.consoleTail(ctx, c, build)
	if err != nil {
		return "", err
	}
	head := fmt.Sprintf("#%d %s", number, status)
	if status == "BUILDING" {
		head += fmt.Sprintf(" (still running after %s; call jenkins_build_wait again)", timeout)
	}
	return head + "\n--- console (last " + fmt.Sprint(tailLines) + " lines) ---\n" + tail, nil
}

// consoleTail streams a build's console and keeps only its last tailLines lines.
func (j *Jenkins) consoleTail(ctx context.Context, c tools.Creds, build string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, build+"/consoleText", nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(c["username"], c["token"])
	resp, err := j.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", upstream.StatusErr("jenkins", resp.StatusCode, b)
	}
	ring := make([]string, 0, tailLines)
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 64<<20))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if len(ring) == tailLines {
			ring = ring[1:]
		}
		ring = append(ring, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("jenkins: read console: %w", err)
	}
	return strings.Join(ring, "\n"), nil
}

// paramValue is one build parameter; Null marks a Jenkins value of null (no value set).
type paramValue struct {
	Name, Value string
	Null        bool
}

func (j *Jenkins) buildParams(ctx context.Context, c tools.Creds, raw string, number int) ([]paramValue, error) {
	u, err := j.jobURL(raw)
	if err != nil {
		return nil, err
	}
	if number <= 0 {
		return nil, errors.New("number is required")
	}
	b, err := j.do(ctx, c, http.MethodGet, fmt.Sprintf("%s/%d/api/json?tree=actions[parameters[name,value]]", u, number), nil, nil, 256<<10)
	if err != nil {
		return nil, err
	}
	var jr struct {
		Actions []struct {
			Parameters []struct {
				Name  string `json:"name"`
				Value any    `json:"value"`
			} `json:"parameters"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(b, &jr); err != nil {
		return nil, fmt.Errorf("jenkins: parse build: %w", err)
	}
	var out []paramValue
	for _, a := range jr.Actions {
		for _, p := range a.Parameters {
			out = append(out, paramValue{p.Name, stringify(p.Value), p.Value == nil})
		}
	}
	return out, nil
}

func (j *Jenkins) Tools() []tools.Tool {
	jobURL := tools.Str("full Jenkins job URL, e.g. " + j.base.String() + "/job/App-Production")
	type jobArgs struct {
		JobURL         string         `json:"jobURL"`
		Limit          int            `json:"limit"`
		Number         int            `json:"number"`
		TimeoutSeconds int            `json:"timeoutSeconds"`
		Params         map[string]any `json:"params"`
	}
	parse := func(raw json.RawMessage) (jobArgs, error) {
		var a jobArgs
		return a, tools.Args(raw, &a)
	}
	return []tools.Tool{
		{
			Name:        "jenkins_job",
			Description: "List a Jenkins job's build parameters (name, type, default, choices). Call this before jenkins_deploy on a parameterized job to know what to pass.",
			Schema:      tools.Object(map[string]any{"jobURL": jobURL}, "jobURL"),
			Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
				a, err := parse(raw)
				if err != nil {
					return "", err
				}
				return j.jobParams(ctx, c, a.JobURL)
			},
		},
		{
			Name:        "jenkins_builds",
			Description: "Read a Jenkins job's recent build history (read-only): build number, result (SUCCESS/FAILURE/BUILDING), timestamp and head commit. Use to confirm the last deploy or check whether a build passed.",
			Schema:      tools.Object(map[string]any{"jobURL": jobURL, "limit": tools.Int("how many recent builds (default 10, max 30)")}, "jobURL"),
			Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
				a, err := parse(raw)
				if err != nil {
					return "", err
				}
				return j.builds(ctx, c, a.JobURL, a.Limit)
			},
		},
		{
			Name:        "jenkins_build_params",
			Description: "Read the parameters a past Jenkins build ran with (read-only). Use before jenkins_rebuild to see exactly what would be replayed.",
			Schema:      tools.Object(map[string]any{"jobURL": jobURL, "number": tools.Int("build number (from jenkins_builds)")}, "jobURL", "number"),
			Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
				a, err := parse(raw)
				if err != nil {
					return "", err
				}
				ps, err := j.buildParams(ctx, c, a.JobURL, a.Number)
				if err != nil {
					return "", err
				}
				if len(ps) == 0 {
					return "build had no parameters (rebuild = plain build of current HEAD)", nil
				}
				var sb strings.Builder
				for _, p := range ps {
					if p.Null {
						fmt.Fprintf(&sb, "%s=(no value)\n", p.Name)
						continue
					}
					fmt.Fprintf(&sb, "%s=%s\n", p.Name, p.Value)
				}
				return sb.String(), nil
			},
		},
		{
			Name:        "jenkins_deploy",
			Description: "Trigger a Jenkins build for a deploy job. MUTATING: starts a real build, so state the job and params and get the human's explicit go-ahead first. Pass params for a parameterized job (get names from jenkins_job); omit params for a plain build. Returns the started build number; follow with jenkins_build_wait for the result.",
			Schema: tools.Object(map[string]any{
				"jobURL": jobURL,
				"params": map[string]any{"type": "object", "description": "build parameters as key/value (for buildWithParameters)", "additionalProperties": map[string]any{"type": "string"}},
			}, "jobURL"),
			Destructive: true,
			Timeout:     startWait + 30*time.Second,
			Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
				a, err := parse(raw)
				if err != nil {
					return "", err
				}
				params := map[string]string{}
				for k, v := range a.Params {
					params[k] = fmt.Sprint(v)
				}
				return j.build(ctx, c, a.JobURL, params)
			},
		},
		{
			Name: "jenkins_build_wait",
			Description: "Wait for a Jenkins build to finish (read-only) and return its result (SUCCESS/FAILURE/ABORTED/UNSTABLE) plus the last 200 console lines. " +
				"If it is still running when timeoutSeconds passes, returns BUILDING; call again to keep waiting. Use after jenkins_deploy with the build number it returned.",
			Schema: tools.Object(map[string]any{
				"jobURL":         jobURL,
				"number":         tools.Int("build number (from jenkins_deploy or jenkins_builds)"),
				"timeoutSeconds": tools.Int("how long to wait (default 300, max 600)"),
			}, "jobURL", "number"),
			Timeout: maxWait + time.Minute,
			Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
				a, err := parse(raw)
				if err != nil {
					return "", err
				}
				return j.waitBuild(ctx, c, a.JobURL, a.Number, time.Duration(a.TimeoutSeconds)*time.Second)
			},
		},
		{
			Name:        "jenkins_rebuild",
			Description: "Rebuild a past Jenkins build with its exact parameters. MUTATING: queues a real build, so get the human's explicit go-ahead first. CAVEAT: a job that builds from git HEAD without a version parameter builds CURRENT head, not the old version; check jenkins_build_params first.",
			Schema:      tools.Object(map[string]any{"jobURL": jobURL, "number": tools.Int("build number to replay (from jenkins_builds)")}, "jobURL", "number"),
			Destructive: true,
			Timeout:     startWait + 30*time.Second,
			Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
				a, err := parse(raw)
				if err != nil {
					return "", err
				}
				ps, err := j.buildParams(ctx, c, a.JobURL, a.Number)
				if err != nil {
					return "", err
				}
				params := map[string]string{}
				for _, p := range ps {
					if p.Null {
						continue // let Jenkins apply the parameter's default
					}
					params[p.Name] = p.Value
				}
				return j.build(ctx, c, a.JobURL, params)
			},
		},
	}
}
