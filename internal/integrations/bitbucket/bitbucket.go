// Package bitbucket exposes Bitbucket Cloud pull request tools, authenticated per user.
package bitbucket

import (
	"bytes"
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

type Bitbucket struct {
	base   string // API root, e.g. https://api.bitbucket.org/2.0
	client *http.Client
}

func New(baseURL string, insecure bool) *Bitbucket {
	return &Bitbucket{base: strings.TrimRight(baseURL, "/"), client: upstream.Client(insecure)}
}

func (b *Bitbucket) System() string { return "bitbucket" }
func (b *Bitbucket) Title() string  { return "Bitbucket" }

func (b *Bitbucket) Fields() []tools.Field {
	return []tools.Field{
		{Name: "token", Label: "API or access token (needs repository:read and pullrequest:write)", Secret: true},
		{Name: "email", Label: "Atlassian email (only for a personal API token; leave empty for an access token)", Optional: true},
	}
}

func (b *Bitbucket) Help() []string {
	return []string{
		"Personal API token (acts as you, works for every repository you can reach): open https://id.atlassian.com/manage-profile/security/api-tokens, " +
			"click Create API token with scopes, choose Bitbucket, and tick read:repository:bitbucket, read:pullrequest:bitbucket and write:pullrequest:bitbucket. " +
			"Paste it as the token and fill in the email of your Atlassian account.",
		"Or a repository access token (one repository only): in the repository open Repository settings, Security, Access tokens, Create, " +
			"tick Repositories: Read and Pull requests: Write. Paste it as the token and leave the email empty.",
		"The token is checked on its first use; if a tool says Bitbucket rejected it, create a new one and save it here again.",
	}
}

// Validate only checks the token is present.
// ponytail: no generic "who am I" call works for repository access tokens, so a bad
// token surfaces on the first tool call as "rejected your credentials, reconnect".
func (b *Bitbucket) Validate(_ context.Context, c tools.Creds) error {
	if strings.TrimSpace(c["token"]) == "" {
		return errors.New("token is required")
	}
	return nil
}

var repoRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

func repoPath(repo string) (string, error) {
	repo = strings.TrimSpace(repo)
	if !repoRe.MatchString(repo) || strings.Contains(repo, "..") {
		return "", fmt.Errorf("repo must be \"workspace/slug\", got %q", repo)
	}
	return "/repositories/" + repo, nil
}

// do sends one API request. body, when not nil, is sent as JSON. out, when not nil,
// receives the decoded JSON response.
func (b *Bitbucket) do(ctx context.Context, c tools.Creds, method, path string, body, out any, limit int64) ([]byte, http.Header, int, error) {
	var rd io.Reader
	if body != nil {
		j, err := json.Marshal(body)
		if err != nil {
			return nil, nil, 0, err
		}
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.base+path, rd)
	if err != nil {
		return nil, nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c["email"] != "" {
		req.SetBasicAuth(c["email"], c["token"])
	} else {
		req.Header.Set("Authorization", "Bearer "+c["token"])
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, nil, 0, err
	}
	if err := upstream.StatusErr("bitbucket", resp.StatusCode, raw); err != nil {
		return nil, nil, resp.StatusCode, err
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return nil, nil, 0, fmt.Errorf("bitbucket: parse %s: %w", path, err)
		}
	}
	return raw, resp.Header, resp.StatusCode, nil
}

type pullRequest struct {
	ID          int    `json:"id"`
	Title       string `json:"title"`
	State       string `json:"state"`
	Description string `json:"description"`
	Author      struct {
		DisplayName string `json:"display_name"`
	} `json:"author"`
	Source struct {
		Branch struct {
			Name string `json:"name"`
		} `json:"branch"`
		Commit struct {
			Hash string `json:"hash"`
		} `json:"commit"`
	} `json:"source"`
	Destination struct {
		Branch struct {
			Name string `json:"name"`
		} `json:"branch"`
	} `json:"destination"`
	MergeCommit *struct {
		Hash string `json:"hash"`
	} `json:"merge_commit"`
	Participants []struct {
		User struct {
			DisplayName string `json:"display_name"`
		} `json:"user"`
		Approved bool   `json:"approved"`
		State    string `json:"state"`
	} `json:"participants"`
	Links struct {
		HTML struct {
			Href string `json:"href"`
		} `json:"html"`
	} `json:"links"`
}

func (p pullRequest) summary() string {
	s := fmt.Sprintf("PR #%d %s: %s\n%s -> %s, source commit %s\n%s",
		p.ID, p.State, p.Title, p.Source.Branch.Name, p.Destination.Branch.Name, p.Source.Commit.Hash, p.Links.HTML.Href)
	if p.MergeCommit != nil && p.MergeCommit.Hash != "" {
		s += "\nmerge commit " + p.MergeCommit.Hash
	}
	return s
}

func (b *Bitbucket) mainBranch(ctx context.Context, c tools.Creds, rp string) (string, error) {
	var r struct {
		Mainbranch struct {
			Name string `json:"name"`
		} `json:"mainbranch"`
	}
	if _, _, _, err := b.do(ctx, c, http.MethodGet, rp+"?fields=mainbranch.name", nil, &r, 64<<10); err != nil {
		return "", err
	}
	if r.Mainbranch.Name == "" {
		return "", errors.New("bitbucket: repository has no main branch")
	}
	return r.Mainbranch.Name, nil
}

func (b *Bitbucket) getPR(ctx context.Context, c tools.Creds, rp string, id int) (pullRequest, error) {
	var p pullRequest
	if id <= 0 {
		return p, errors.New("id is required")
	}
	_, _, _, err := b.do(ctx, c, http.MethodGet, fmt.Sprintf("%s/pullrequests/%d", rp, id), nil, &p, 1<<20)
	return p, err
}

func (b *Bitbucket) createPR(ctx context.Context, c tools.Creds, repo, source, dest, title, desc string) (string, error) {
	rp, err := repoPath(repo)
	if err != nil {
		return "", err
	}
	if source = strings.TrimSpace(source); source == "" || strings.TrimSpace(title) == "" {
		return "", errors.New("source_branch and title are required")
	}
	main, err := b.mainBranch(ctx, c, rp)
	if err != nil {
		return "", err
	}
	if dest == "" {
		dest = main
	}
	if dest != main {
		return "", fmt.Errorf("refused: destination must be the main branch %q, got %q", main, dest)
	}
	if source == main {
		return "", errors.New("refused: source_branch is the main branch")
	}
	var open struct {
		Values []pullRequest `json:"values"`
	}
	q := url.Values{"state": {"OPEN"}, "q": {fmt.Sprintf("source.branch.name=%q", source)}}
	if _, _, _, err := b.do(ctx, c, http.MethodGet, rp+"/pullrequests?"+q.Encode(), nil, &open, 1<<20); err != nil {
		return "", err
	}
	for _, p := range open.Values {
		if p.Source.Branch.Name == source && p.Destination.Branch.Name == dest {
			return "already open (not created again):\n" + p.summary(), nil
		}
	}
	var p pullRequest
	body := map[string]any{
		"title":       title,
		"description": desc,
		"source":      map[string]any{"branch": map[string]string{"name": source}},
		"destination": map[string]any{"branch": map[string]string{"name": dest}},
	}
	if _, _, _, err := b.do(ctx, c, http.MethodPost, rp+"/pullrequests", body, &p, 1<<20); err != nil {
		return "", err
	}
	return "created:\n" + p.summary(), nil
}

func (b *Bitbucket) prInfo(ctx context.Context, c tools.Creds, repo string, id int) (string, error) {
	rp, err := repoPath(repo)
	if err != nil {
		return "", err
	}
	p, err := b.getPR(ctx, c, rp, id)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	sb.WriteString(p.summary())
	fmt.Fprintf(&sb, "\nauthor %s", p.Author.DisplayName)
	var approvers []string
	for _, pt := range p.Participants {
		if pt.Approved {
			approvers = append(approvers, pt.User.DisplayName)
		} else if pt.State == "changes_requested" {
			fmt.Fprintf(&sb, "\nchanges requested by %s", pt.User.DisplayName)
		}
	}
	fmt.Fprintf(&sb, "\napprovals (%d): %s", len(approvers), strings.Join(approvers, ", "))
	var ds struct {
		Values []struct {
			Status       string `json:"status"`
			LinesAdded   int    `json:"lines_added"`
			LinesRemoved int    `json:"lines_removed"`
			Old          *struct {
				Path string `json:"path"`
			} `json:"old"`
			New *struct {
				Path string `json:"path"`
			} `json:"new"`
		} `json:"values"`
		Next string `json:"next"`
	}
	if _, _, _, err := b.do(ctx, c, http.MethodGet, fmt.Sprintf("%s/pullrequests/%d/diffstat?pagelen=500", rp, id), nil, &ds, 4<<20); err != nil {
		return "", err
	}
	sb.WriteString("\nfiles:")
	for _, f := range ds.Values {
		path := ""
		if f.New != nil {
			path = f.New.Path
		} else if f.Old != nil {
			path = f.Old.Path
		}
		fmt.Fprintf(&sb, "\n  %s %s +%d -%d", f.Status, path, f.LinesAdded, f.LinesRemoved)
	}
	if ds.Next != "" {
		sb.WriteString("\n  (more files not listed)")
	}
	if p.Description != "" {
		sb.WriteString("\ndescription:\n")
		sb.WriteString(p.Description)
	}
	return sb.String(), nil
}

func (b *Bitbucket) prDiff(ctx context.Context, c tools.Creds, repo string, id int) (string, error) {
	rp, err := repoPath(repo)
	if err != nil {
		return "", err
	}
	if id <= 0 {
		return "", errors.New("id is required")
	}
	raw, _, _, err := b.do(ctx, c, http.MethodGet, fmt.Sprintf("%s/pullrequests/%d/diff", rp, id), nil, nil, tools.MaxOutput+1)
	if err != nil {
		return "", err
	}
	if len(raw) > tools.MaxOutput {
		return string(raw[:tools.MaxOutput-200]) + "\n... diff truncated; use bitbucket_pr_get for the file list", nil
	}
	if len(raw) == 0 {
		return "empty diff", nil
	}
	return string(raw), nil
}

// sameCommit compares a full or short hash with Bitbucket's (usually 12-char) one.
func sameCommit(expected, actual string) bool {
	expected, actual = strings.ToLower(strings.TrimSpace(expected)), strings.ToLower(actual)
	if len(expected) < 12 || len(actual) < 12 {
		return false
	}
	return strings.HasPrefix(expected, actual) || strings.HasPrefix(actual, expected)
}

var (
	mergePoll = 2 * time.Second
	taskRe    = regexp.MustCompile(`/merge/task-status/([A-Za-z0-9_-]+)$`)
)

func (b *Bitbucket) mergePR(ctx context.Context, c tools.Creds, repo string, id int, expected, strategy string, closeSource bool) (string, error) {
	rp, err := repoPath(repo)
	if err != nil {
		return "", err
	}
	if strategy == "" {
		strategy = "merge_commit"
	}
	if strategy != "merge_commit" && strategy != "squash" {
		return "", fmt.Errorf("strategy must be merge_commit or squash, got %q", strategy)
	}
	if len(strings.TrimSpace(expected)) < 12 {
		return "", errors.New("expected_source_commit is required (at least 12 hex characters, from bitbucket_pr_get)")
	}
	p, err := b.getPR(ctx, c, rp, id)
	if err != nil {
		return "", err
	}
	if p.State != "OPEN" {
		return "", fmt.Errorf("refused: PR #%d is %s", id, p.State)
	}
	main, err := b.mainBranch(ctx, c, rp)
	if err != nil {
		return "", err
	}
	if p.Destination.Branch.Name != main {
		return "", fmt.Errorf("refused: PR #%d targets %q, not the main branch %q", id, p.Destination.Branch.Name, main)
	}
	// ponytail: Bitbucket's merge endpoint takes no expected head, so a push landing
	// between this check and the merge call still gets merged (a millisecond window).
	if !sameCommit(expected, p.Source.Commit.Hash) {
		return "", fmt.Errorf("refused: PR #%d head is now %s, not the reviewed %s; review again", id, p.Source.Commit.Hash, expected)
	}
	body := map[string]any{"type": "pullrequest", "merge_strategy": strategy, "close_source_branch": closeSource}
	var merged pullRequest
	_, hdr, code, err := b.do(ctx, c, http.MethodPost, fmt.Sprintf("%s/pullrequests/%d/merge", rp, id), body, &merged, 1<<20)
	if err != nil {
		return "", err
	}
	if code == http.StatusAccepted {
		m := taskRe.FindStringSubmatch(hdr.Get("Location"))
		if m == nil {
			return "merge accepted and running in the background; check bitbucket_pr_get", nil
		}
		if merged, err = b.waitMerge(ctx, c, rp, id, m[1]); err != nil {
			return "", err
		}
	}
	return "merged:\n" + merged.summary(), nil
}

// waitMerge polls an async merge task. The task URL is rebuilt from the
// configured base, never taken from the Location header.
func (b *Bitbucket) waitMerge(ctx context.Context, c tools.Creds, rp string, id int, task string) (pullRequest, error) {
	for {
		var t struct {
			TaskStatus  string      `json:"task_status"`
			MergeResult pullRequest `json:"merge_result"`
		}
		if _, _, _, err := b.do(ctx, c, http.MethodGet, fmt.Sprintf("%s/pullrequests/%d/merge/task-status/%s", rp, id, task), nil, &t, 1<<20); err != nil {
			return pullRequest{}, err
		}
		if t.TaskStatus == "SUCCESS" {
			return t.MergeResult, nil
		}
		if t.TaskStatus != "PENDING" {
			return pullRequest{}, fmt.Errorf("bitbucket: merge task ended as %q", t.TaskStatus)
		}
		select {
		case <-ctx.Done():
			return pullRequest{}, ctx.Err()
		case <-time.After(mergePoll):
		}
	}
}

func (b *Bitbucket) comment(ctx context.Context, c tools.Creds, repo string, id int, text string) (string, error) {
	rp, err := repoPath(repo)
	if err != nil {
		return "", err
	}
	if id <= 0 || strings.TrimSpace(text) == "" {
		return "", errors.New("id and text are required")
	}
	var r struct {
		ID    int `json:"id"`
		Links struct {
			HTML struct {
				Href string `json:"href"`
			} `json:"html"`
		} `json:"links"`
	}
	body := map[string]any{"content": map[string]string{"raw": text}}
	if _, _, _, err := b.do(ctx, c, http.MethodPost, fmt.Sprintf("%s/pullrequests/%d/comments", rp, id), body, &r, 1<<20); err != nil {
		return "", err
	}
	return fmt.Sprintf("comment %d added: %s", r.ID, r.Links.HTML.Href), nil
}

func (b *Bitbucket) Tools() []tools.Tool {
	type prArgs struct {
		Repo              string `json:"repo"`
		ID                int    `json:"id"`
		SourceBranch      string `json:"source_branch"`
		Destination       string `json:"destination"`
		Title             string `json:"title"`
		Description       string `json:"description"`
		ExpectedCommit    string `json:"expected_source_commit"`
		Strategy          string `json:"strategy"`
		CloseSourceBranch bool   `json:"close_source_branch"`
		Text              string `json:"text"`
	}
	parse := func(raw json.RawMessage) (prArgs, error) {
		var a prArgs
		return a, tools.Args(raw, &a)
	}
	repo := tools.Str(`repository as "workspace/slug", e.g. "acme/web"`)
	id := tools.Int("pull request id")
	return []tools.Tool{
		{
			Name: "bitbucket_pr_create",
			Description: "Open a pull request from a branch into the repository's main branch. MUTATING. " +
				"Idempotent: if an open PR from that branch already exists it is returned instead. Returns the id, URL and source commit.",
			Schema: tools.Object(map[string]any{
				"repo": repo, "source_branch": tools.Str("branch to merge from, e.g. fix/login-timeout"),
				"title": tools.Str("PR title"), "description": tools.Str("PR description (markdown)"),
				"destination": tools.Str("target branch; must be the main branch (default)"),
			}, "repo", "source_branch", "title"),
			Destructive: true,
			Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
				a, err := parse(raw)
				if err != nil {
					return "", err
				}
				return b.createPR(ctx, c, a.Repo, a.SourceBranch, a.Destination, a.Title, a.Description)
			},
		},
		{
			Name:        "bitbucket_pr_get",
			Description: "Read a pull request (read-only): state, branches, source commit hash (pass it to bitbucket_pr_merge), approvals, changed files and description.",
			Schema:      tools.Object(map[string]any{"repo": repo, "id": id}, "repo", "id"),
			Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
				a, err := parse(raw)
				if err != nil {
					return "", err
				}
				return b.prInfo(ctx, c, a.Repo, a.ID)
			},
		},
		{
			Name:        "bitbucket_pr_diff",
			Description: "Read a pull request's unified diff (read-only), truncated at 100KB.",
			Schema:      tools.Object(map[string]any{"repo": repo, "id": id}, "repo", "id"),
			Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
				a, err := parse(raw)
				if err != nil {
					return "", err
				}
				return b.prDiff(ctx, c, a.Repo, a.ID)
			},
		},
		{
			Name: "bitbucket_pr_merge",
			Description: "Merge a pull request into the main branch. MUTATING and irreversible: get the human's explicit go-ahead first. " +
				"Refused unless the PR is open, targets the main branch, and its head is still expected_source_commit (the commit that was reviewed).",
			Schema: tools.Object(map[string]any{
				"repo": repo, "id": id,
				"expected_source_commit": tools.Str("source commit hash that was reviewed (from bitbucket_pr_get)"),
				"strategy":               tools.Str("merge_commit (default) or squash"),
				"close_source_branch":    map[string]any{"type": "boolean", "description": "delete the source branch after merging (default false)"},
			}, "repo", "id", "expected_source_commit"),
			Destructive: true,
			Timeout:     2 * time.Minute,
			Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
				a, err := parse(raw)
				if err != nil {
					return "", err
				}
				return b.mergePR(ctx, c, a.Repo, a.ID, a.ExpectedCommit, a.Strategy, a.CloseSourceBranch)
			},
		},
		{
			Name:        "bitbucket_pr_comment",
			Description: "Add a comment to a pull request. MUTATING (visible to the team).",
			Schema:      tools.Object(map[string]any{"repo": repo, "id": id, "text": tools.Str("comment text (markdown)")}, "repo", "id", "text"),
			Destructive: true,
			Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
				a, err := parse(raw)
				if err != nil {
					return "", err
				}
				return b.comment(ctx, c, a.Repo, a.ID, a.Text)
			},
		},
	}
}
