// Package argocd exposes ArgoCD application status, sync and rollout-watch tools.
package argocd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/upstream"
)

type ArgoCD struct {
	base      string
	client    *http.Client
	pollEvery time.Duration
}

func New(baseURL string, insecure bool) *ArgoCD {
	return &ArgoCD{base: strings.TrimRight(baseURL, "/"), client: upstream.Client(insecure), pollEvery: 10 * time.Second}
}

func (a *ArgoCD) System() string { return "argocd" }
func (a *ArgoCD) Title() string  { return "ArgoCD" }

func (a *ArgoCD) Fields() []tools.Field {
	return []tools.Field{
		{Name: "token", Label: "API token (or leave empty and use username + password)", Secret: true, Optional: true},
		{Name: "username", Label: "Username (LDAP)", Optional: true},
		{Name: "password", Label: "Password", Secret: true, Optional: true},
	}
}

func (a *ArgoCD) Help() []string {
	return []string{
		"Easiest: leave the token empty and enter the username and password you use on " + a.base + " (the LDAP login button).",
		"Or, if your account may create tokens: in " + a.base + " open User Info, then generate a token, and paste it as the API token.",
	}
}
func (a *ArgoCD) Validate(ctx context.Context, c tools.Creds) error {
	tok, err := a.bearer(ctx, c)
	if err != nil {
		return err
	}
	b, err := a.do(ctx, tok, http.MethodGet, "/api/v1/session/userinfo", "")
	if err != nil {
		return err
	}
	var ui struct {
		LoggedIn bool `json:"loggedIn"`
	}
	if json.Unmarshal(b, &ui) != nil || !ui.LoggedIn {
		return fmt.Errorf("argocd: not logged in: %w", upstream.ErrUnauthorized)
	}
	return nil
}

// bearer returns the API token, logging in through Dex when the user stored
// username + password.
// ponytail: logs in once per tool call; cache the session per user if Dex starts rate-limiting.
func (a *ArgoCD) bearer(ctx context.Context, c tools.Creds) (string, error) {
	if c["token"] != "" {
		return c["token"], nil
	}
	if c["username"] == "" || c["password"] == "" {
		return "", errors.New("argocd: set an API token, or username and password")
	}
	return a.dexLogin(ctx, c["username"], c["password"])
}

var formAction = regexp.MustCompile(`(?i)<form[^>]*action="([^"]+)"`)

// dexLogin scripts the browser SSO flow: /auth/login lands on Dex's LDAP form,
// and posting it makes ArgoCD set the argocd.token cookie.
// ponytail: assumes a single Dex connector, so /auth/login goes straight to the form.
func (a *ArgoCD) dexLogin(ctx context.Context, user, pass string) (string, error) {
	base, err := url.Parse(a.base)
	if err != nil {
		return "", err
	}
	jar, _ := cookiejar.New(nil)
	client := *a.client
	client.Jar = jar
	// The password must never leave the configured origin, so refuse any redirect that
	// leaves it. Keep Go's default limit of 10 redirects.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("argocd login: stopped after 10 redirects")
		}
		if !sameOrigin(req.URL, base) {
			return fmt.Errorf("argocd login: refusing redirect to %s", req.URL.Host)
		}
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base+"/auth/login", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	m := formAction.FindSubmatch(body)
	if m == nil {
		return "", errors.New("argocd login: no login form found (single LDAP connector expected)")
	}
	action, err := resp.Request.URL.Parse(html.UnescapeString(string(m[1])))
	if err != nil {
		return "", err
	}
	if !sameOrigin(action, base) {
		return "", fmt.Errorf("argocd login: refusing to send credentials to %s", action.Host)
	}

	form := url.Values{"login": {user}, "password": {pass}}
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, action.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = client.Do(req)
	if err != nil {
		return "", err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()

	for _, ck := range jar.Cookies(base) {
		if ck.Name == "argocd.token" && ck.Value != "" {
			return ck.Value, nil
		}
	}
	return "", fmt.Errorf("argocd login failed, check username and password: %w", upstream.ErrUnauthorized)
}

// sameOrigin reports whether u has the same scheme and host as base.
func sameOrigin(u, base *url.URL) bool {
	return u.Scheme == base.Scheme && u.Host == base.Host
}

func (a *ArgoCD) do(ctx context.Context, tok, method, path, body string) ([]byte, error) {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, r)
	if err != nil {
		return nil, err
	}
	upstream.SetAuth(req, map[string]string{"token": tok})
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	return b, upstream.StatusErr("argocd", resp.StatusCode, b)
}

type appStatus struct {
	Sync, Health, Revision, FullRevision, Message, Resources, FinishedAt string
	Images                                                               []string
}

func (s appStatus) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "sync=%s health=%s revision=%s", s.Sync, s.Health, s.Revision)
	if s.Resources != "" {
		fmt.Fprintf(&b, " resources=[%s]", s.Resources)
	}
	if s.FinishedAt != "" {
		fmt.Fprintf(&b, " lastSync=%s", s.FinishedAt)
	}
	if s.Message != "" {
		b.WriteString("\n" + s.Message)
	}
	if len(s.Images) > 0 {
		b.WriteString("\nimages:\n  " + strings.Join(s.Images, "\n  "))
	}
	return b.String()
}

func (s appStatus) fingerprint() string {
	imgs := append([]string(nil), s.Images...)
	sort.Strings(imgs)
	return s.Revision + "|" + strings.Join(imgs, ",")
}

func parseApp(body []byte) (appStatus, error) {
	var a struct {
		Status struct {
			Sync struct {
				Status   string `json:"status"`
				Revision string `json:"revision"`
			} `json:"sync"`
			Health struct {
				Status string `json:"status"`
			} `json:"health"`
			OperationState struct {
				Phase      string `json:"phase"`
				Message    string `json:"message"`
				FinishedAt string `json:"finishedAt"`
			} `json:"operationState"`
			Summary struct {
				Images []string `json:"images"`
			} `json:"summary"`
			Resources []struct {
				Status string `json:"status"`
				Health struct {
					Status string `json:"status"`
				} `json:"health"`
			} `json:"resources"`
		} `json:"status"`
	}
	if err := json.Unmarshal(body, &a); err != nil {
		return appStatus{}, fmt.Errorf("argocd: parse app: %w", err)
	}
	rev := a.Status.Sync.Revision
	full := rev
	if len(rev) > 10 {
		rev = rev[:10]
	}
	msg := a.Status.OperationState.Message
	if a.Status.OperationState.Phase != "" {
		msg = a.Status.OperationState.Phase + " · " + msg
	}
	synced, healthy := 0, 0
	for _, r := range a.Status.Resources {
		if r.Status == "Synced" {
			synced++
		}
		if r.Health.Status == "Healthy" {
			healthy++
		}
	}
	res := ""
	if total := len(a.Status.Resources); total > 0 {
		res = fmt.Sprintf("%d/%d synced · %d healthy", synced, total, healthy)
	}
	return appStatus{
		Sync: a.Status.Sync.Status, Health: a.Status.Health.Status, Revision: rev, FullRevision: full,
		Message: strings.TrimSpace(msg), Resources: res, FinishedAt: a.Status.OperationState.FinishedAt,
		Images: a.Status.Summary.Images,
	}, nil
}

func (a *ArgoCD) app(ctx context.Context, tok, name, refresh string) (appStatus, error) {
	if strings.TrimSpace(name) == "" {
		return appStatus{}, errors.New("app is required")
	}
	path := "/api/v1/applications/" + url.PathEscape(name)
	if refresh != "" {
		path += "?refresh=" + url.QueryEscape(refresh)
	}
	b, err := a.do(ctx, tok, http.MethodGet, path, "")
	if err != nil {
		return appStatus{}, err
	}
	return parseApp(b)
}

// watch waits for a NEW version to settle. It baselines the current
// revision + images, then polls until they change and the app is
// Synced+Healthy (success), turns Degraded, or the timeout passes. Transient
// poll errors are skipped; a 401/403 stops the watch at once.
func (a *ArgoCD) watch(ctx context.Context, tok, name string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	wait := func() bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(a.pollEvery):
			return time.Now().Before(deadline)
		}
	}
	var base appStatus
	for {
		s, err := a.app(ctx, tok, name, "")
		if errors.Is(err, upstream.ErrUnauthorized) {
			return "", err
		}
		if err == nil {
			base = s
			break
		}
		if !wait() {
			return name + ": timeout, could not read the app: " + err.Error(), nil
		}
	}
	fp := base.fingerprint()
	for wait() {
		s, err := a.app(ctx, tok, name, "")
		if errors.Is(err, upstream.ErrUnauthorized) {
			return "", err
		}
		if err != nil {
			continue
		}
		if s.Health == "Degraded" {
			return name + ": degraded, " + s.Message, nil
		}
		if s.fingerprint() != fp && s.Sync == "Synced" && s.Health == "Healthy" {
			return name + ": success, new version is up: " + strings.Join(s.Images, ", "), nil
		}
	}
	return name + ": timeout, no new version became healthy in time", nil
}

func watchMinutes(m int) int {
	switch {
	case m <= 0:
		return 3
	case m > 5:
		return 5
	}
	return m
}

func (a *ArgoCD) Tools() []tools.Tool {
	app := tools.Str("ArgoCD application name")
	type args struct {
		App              string `json:"app"`
		Refresh          string `json:"refresh"`
		TimeoutMinutes   int    `json:"timeoutMinutes"`
		ExpectedRevision string `json:"expected_revision"`
	}
	prep := func(ctx context.Context, c tools.Creds, raw json.RawMessage) (args, string, error) {
		var x args
		if err := tools.Args(raw, &x); err != nil {
			return x, "", err
		}
		tok, err := a.bearer(ctx, c)
		return x, tok, err
	}
	return []tools.Tool{
		{
			Name:        "argocd_status",
			Description: "Get an ArgoCD application's sync + health status (read-only). Set refresh='hard' to force ArgoCD to re-compare against git first (e.g. right after a commit).",
			Schema:      tools.Object(map[string]any{"app": app, "refresh": tools.Str("optional: 'normal' or 'hard'")}, "app"),
			Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
				x, tok, err := prep(ctx, c, raw)
				if err != nil {
					return "", err
				}
				s, err := a.app(ctx, tok, x.App, x.Refresh)
				if err != nil {
					return "", err
				}
				return s.String(), nil
			},
		},
		{
			Name:        "argocd_sync",
			Description: "Trigger an ArgoCD sync for an application. MUTATING: applies the desired git state to the cluster (deploys), so get the human's explicit go-ahead first. Returns the fresh status after starting.",
			Schema: tools.Object(map[string]any{
				"app":               app,
				"expected_revision": tools.Str("optional git commit (7+ characters) you expect Argo CD to deploy; the sync is refused if the app resolves to another commit"),
			}, "app"),
			Destructive: true,
			Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
				x, tok, err := prep(ctx, c, raw)
				if err != nil {
					return "", err
				}
				if strings.TrimSpace(x.App) == "" {
					return "", errors.New("app is required")
				}
				body := "{}"
				if x.ExpectedRevision != "" {
					want := strings.ToLower(strings.TrimSpace(x.ExpectedRevision))
					if len(want) < 7 {
						return "", errors.New("expected_revision needs at least 7 characters")
					}
					s, err := a.app(ctx, tok, x.App, "normal")
					if err != nil {
						return "", err
					}
					if !strings.HasPrefix(strings.ToLower(s.FullRevision), want) {
						return "", tools.Refuse("argocd_sync: app %s resolves to revision %s, not %s; check the app's target before syncing", x.App, s.Revision, want)
					}
					// Pin the sync to the checked commit, so a push in between cannot change what deploys.
					b, _ := json.Marshal(map[string]string{"revision": s.FullRevision})
					body = string(b)
				}
				if _, err := a.do(ctx, tok, http.MethodPost, "/api/v1/applications/"+url.PathEscape(x.App)+"/sync", body); err != nil {
					return "", err
				}
				s, err := a.app(ctx, tok, x.App, "")
				if err != nil {
					// The sync itself succeeded; do not report a failure that would invite a re-trigger.
					return fmt.Sprintf("sync triggered (status unavailable: %v)", err), nil
				}
				return "sync triggered.\n" + s.String(), nil
			},
		},
		{
			Name:        "argocd_watch",
			Description: "Wait until a NEW version of an ArgoCD app is rolled out. Baselines the current images/revision, then blocks until they change and the app is Synced+Healthy (success), turns Degraded (failure), or the timeout passes. Call right after triggering a deploy.",
			Schema:      tools.Object(map[string]any{"app": app, "timeoutMinutes": tools.Int("how long to wait (default 3, max 5)")}, "app"),
			Timeout:     6 * time.Minute,
			Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
				x, tok, err := prep(ctx, c, raw)
				if err != nil {
					return "", err
				}
				return a.watch(ctx, tok, x.App, time.Duration(watchMinutes(x.TimeoutMinutes))*time.Minute)
			},
		},
	}
}
