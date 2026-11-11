// Package argocd exposes ArgoCD application status, sync and rollout-watch tools.
package argocd

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	key       []byte // derives each sign-in link's PKCE verifier from its state
}

// key is a server secret; New derives its own key from it, so it is never used
// for anything else.
func New(baseURL string, insecure bool, key []byte) *ArgoCD {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("valetkey argocd pkce"))
	return &ArgoCD{base: strings.TrimRight(baseURL, "/"), client: upstream.Client(insecure), pollEvery: 10 * time.Second, key: m.Sum(nil)}
}

func (a *ArgoCD) System() string { return "argocd" }
func (a *ArgoCD) Title() string  { return "ArgoCD" }

func (a *ArgoCD) Fields() []tools.Field {
	return []tools.Field{
		{Name: "callback", Label: "The address you land on after signing in (http://localhost:8085/auth/callback?code=…)", Optional: true},
		{Name: "token", Label: "Or an API token", Secret: true, Optional: true},
	}
}

func (a *ArgoCD) Help() []string {
	return []string{
		"Click Sign in to ArgoCD. If your browser is already signed in to the SSO behind ArgoCD, it goes straight through.",
		"You land on a page at http://localhost:8085 that does not load. That is expected: copy the whole address from the address bar and paste it above. The sign-in lasts about a day; connect again when ArgoCD asks.",
		"Or, if you have a token that does not expire (a project role token, or a local account's API token on " + a.base + "), paste it as the API token.",
	}
}

// The ArgoCD CLI's Dex client: public, and only allowed to send the browser
// back to localhost, which is why the user pastes the address they land on.
const (
	cliClient   = "argo-cd-cli"
	cliRedirect = "http://localhost:8085/auth/callback"
)

// verifier is the PKCE verifier of the sign-in link with this state. Deriving
// it keeps no state on the server and never shows the verifier to the browser.
func (a *ArgoCD) verifier(state string) string {
	m := hmac.New(sha256.New, a.key)
	m.Write([]byte(state))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// SignInURL starts the ArgoCD SSO login, as `argocd login --sso` does.
func (a *ArgoCD) SignInURL() string {
	state := rand.Text()
	sum := sha256.Sum256([]byte(a.verifier(state)))
	q := url.Values{
		"client_id": {cliClient}, "redirect_uri": {cliRedirect}, "response_type": {"code"},
		"scope": {"openid profile email groups offline_access"}, "state": {state},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
	}
	return a.base + "/api/dex/auth?" + q.Encode()
}

// Exchange turns a pasted sign-in address into an ArgoCD token. An API token
// is kept as it is.
// ponytail: stores only the ID token, which lasts about a day; Dex here cannot refresh it.
func (a *ArgoCD) Exchange(ctx context.Context, c tools.Creds) (tools.Creds, error) {
	pasted := strings.TrimSpace(c["callback"])
	if pasted == "" {
		return tools.Creds{"token": c["token"]}, nil
	}
	u, err := url.Parse(pasted)
	if err != nil {
		return nil, errors.New("paste the whole address you landed on")
	}
	q := u.Query()
	if e := q.Get("error"); e != "" {
		return nil, fmt.Errorf("ArgoCD said %s", e)
	}
	code, state := q.Get("code"), q.Get("state")
	if code == "" || state == "" {
		return nil, errors.New("that address has no sign-in code; paste the whole address you landed on")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cliRedirect},
		"client_id": {cliClient}, "code_verifier": {a.verifier(state)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base+"/api/dex/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok) != nil || tok.IDToken == "" {
		return nil, fmt.Errorf("ArgoCD refused the sign-in code (HTTP %d); it works once and expires quickly, so sign in again and paste the new address", resp.StatusCode)
	}
	return tools.Creds{"token": tok.IDToken}, nil
}

func (a *ArgoCD) Validate(ctx context.Context, c tools.Creds) error {
	tok, err := a.bearer(c)
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

// bearer is the stored token. A login saved as username and password, from
// before valetkey signed in through SSO, no longer works and asks for a new one.
func (a *ArgoCD) bearer(c tools.Creds) (string, error) {
	if c["token"] == "" {
		return "", fmt.Errorf("argocd: sign in again on the connect page: %w", upstream.ErrUnauthorized)
	}
	return c["token"], nil
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
		tok, err := a.bearer(c)
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
