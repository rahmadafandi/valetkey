// Package gitlab exposes GitLab merge request tools, authenticated per user.
package gitlab

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

	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/upstream"
)

type GitLab struct {
	base   string // instance root, e.g. https://gitlab.com
	client *http.Client
}

func New(baseURL string, insecure bool) *GitLab {
	return &GitLab{base: strings.TrimRight(baseURL, "/") + "/api/v4", client: upstream.Client(insecure)}
}

func (g *GitLab) System() string { return "gitlab" }
func (g *GitLab) Title() string  { return "GitLab" }

func (g *GitLab) Fields() []tools.Field {
	return []tools.Field{{Name: "token", Label: "Access token (scope api)", Secret: true}}
}

func (g *GitLab) Help() []string {
	return []string{
		"Project access token (one project only, acts as a bot user): in the project open Settings, Access tokens, Add new token, " +
			"pick the role Developer and tick the scope api. Pick Maintainer if only maintainers may merge into the default branch.",
		"Or a personal access token (acts as you, works for every project you can reach): open your avatar, Edit profile, Access tokens, " +
			"Add new token, and tick the scope api.",
		"GitLab has no narrower scope that can open, comment on or merge a merge request, so limit what an agent reaches with the token's scope in valetkey.",
	}
}

func (g *GitLab) Validate(ctx context.Context, c tools.Creds) error {
	if strings.TrimSpace(c["token"]) == "" {
		return errors.New("token is required")
	}
	_, err := g.do(ctx, c, http.MethodGet, "/user", nil, nil, 64<<10)
	// A fine-grained token without "User: Read" is a real token that GitLab
	// recognised; what it may reach shows on the first tool call.
	if err != nil && strings.Contains(err.Error(), "insufficient_granular_scope") {
		return nil
	}
	return err
}

var projectRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)+$`)

// projectPath turns a full project path into its API path. A numeric project ID
// is not accepted: a token's scope names paths, and an ID would go around it.
func projectPath(project string) (string, error) {
	project = strings.TrimSpace(project)
	if !projectRe.MatchString(project) || strings.Contains(project, "..") {
		return "", fmt.Errorf("project must be its full path such as \"group/app\", got %q", project)
	}
	return "/projects/" + url.PathEscape(project), nil
}

// do sends one API request. body, when not nil, is sent as JSON. out, when not nil,
// receives the decoded JSON response.
func (g *GitLab) do(ctx context.Context, c tools.Creds, method, path string, body, out any, limit int64) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		j, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequestWithContext(ctx, method, g.base+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("PRIVATE-TOKEN", c["token"])
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	if err := upstream.StatusErr("gitlab", resp.StatusCode, raw); err != nil {
		return nil, err
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return nil, fmt.Errorf("gitlab: parse %s: %w", path, err)
		}
	}
	return raw, nil
}

type mergeRequest struct {
	IID         int    `json:"iid"`
	Title       string `json:"title"`
	State       string `json:"state"` // opened, closed, locked or merged
	Description string `json:"description"`
	Author      struct {
		Name string `json:"name"`
	} `json:"author"`
	SourceBranch string `json:"source_branch"`
	TargetBranch string `json:"target_branch"`
	SHA          string `json:"sha"`
	MergeCommit  string `json:"merge_commit_sha"`
	SquashCommit string `json:"squash_commit_sha"`
	MergeStatus  string `json:"detailed_merge_status"`
	WebURL       string `json:"web_url"`
}

func (m mergeRequest) summary() string {
	s := fmt.Sprintf("MR !%d %s: %s\n%s -> %s, source commit %s\n%s",
		m.IID, m.State, m.Title, m.SourceBranch, m.TargetBranch, m.SHA, m.WebURL)
	if m.MergeCommit != "" {
		s += "\nmerge commit " + m.MergeCommit
	} else if m.SquashCommit != "" {
		s += "\nmerge commit " + m.SquashCommit
	}
	return s
}

func (g *GitLab) defaultBranch(ctx context.Context, c tools.Creds, pp string) (string, error) {
	var p struct {
		DefaultBranch string `json:"default_branch"`
	}
	if _, err := g.do(ctx, c, http.MethodGet, pp, nil, &p, 1<<20); err != nil {
		return "", err
	}
	if p.DefaultBranch == "" {
		return "", errors.New("gitlab: project has no default branch")
	}
	return p.DefaultBranch, nil
}

func (g *GitLab) getMR(ctx context.Context, c tools.Creds, pp string, id int) (mergeRequest, error) {
	var m mergeRequest
	if id <= 0 {
		return m, errors.New("id is required")
	}
	_, err := g.do(ctx, c, http.MethodGet, fmt.Sprintf("%s/merge_requests/%d", pp, id), nil, &m, 1<<20)
	return m, err
}

func (g *GitLab) createMR(ctx context.Context, c tools.Creds, project, source, dest, title, desc string) (string, error) {
	pp, err := projectPath(project)
	if err != nil {
		return "", err
	}
	if source = strings.TrimSpace(source); source == "" || strings.TrimSpace(title) == "" {
		return "", errors.New("source_branch and title are required")
	}
	main, err := g.defaultBranch(ctx, c, pp)
	if err != nil {
		return "", err
	}
	if dest == "" {
		dest = main
	}
	if dest != main {
		return "", fmt.Errorf("refused: destination must be the default branch %q, got %q", main, dest)
	}
	if source == main {
		return "", errors.New("refused: source_branch is the default branch")
	}
	var open []mergeRequest
	q := url.Values{"state": {"opened"}, "source_branch": {source}, "target_branch": {dest}}
	if _, err := g.do(ctx, c, http.MethodGet, pp+"/merge_requests?"+q.Encode(), nil, &open, 1<<20); err != nil {
		return "", err
	}
	for _, m := range open {
		if m.SourceBranch == source && m.TargetBranch == dest {
			return "already open (not created again):\n" + m.summary(), nil
		}
	}
	var m mergeRequest
	body := map[string]any{"source_branch": source, "target_branch": dest, "title": title, "description": desc}
	if _, err := g.do(ctx, c, http.MethodPost, pp+"/merge_requests", body, &m, 1<<20); err != nil {
		return "", err
	}
	return "created:\n" + m.summary(), nil
}

type fileDiff struct {
	OldPath string `json:"old_path"`
	NewPath string `json:"new_path"`
	Diff    string `json:"diff"`
	New     bool   `json:"new_file"`
	Renamed bool   `json:"renamed_file"`
	Deleted bool   `json:"deleted_file"`
}

const diffPage = 100

// diffs reads a merge request's changed files, up to pages pages of diffPage.
// more says the last page was full, so files may be missing.
// ponytail: needs GitLab 15.7 or later; older servers only have /changes.
func (g *GitLab) diffs(ctx context.Context, c tools.Creds, pp string, id, pages int) (files []fileDiff, more bool, err error) {
	for page := 1; page <= pages; page++ {
		var got []fileDiff
		path := fmt.Sprintf("%s/merge_requests/%d/diffs?per_page=%d&page=%d", pp, id, diffPage, page)
		if _, err := g.do(ctx, c, http.MethodGet, path, nil, &got, 8<<20); err != nil {
			return nil, false, err
		}
		files = append(files, got...)
		if more = len(got) == diffPage; !more {
			break
		}
	}
	return files, more, nil
}

func (g *GitLab) mrInfo(ctx context.Context, c tools.Creds, project string, id int) (string, error) {
	pp, err := projectPath(project)
	if err != nil {
		return "", err
	}
	m, err := g.getMR(ctx, c, pp, id)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	sb.WriteString(m.summary())
	fmt.Fprintf(&sb, "\nauthor %s", m.Author.Name)
	if m.MergeStatus != "" {
		fmt.Fprintf(&sb, "\nmerge status %s", m.MergeStatus)
	}
	var ap struct {
		ApprovedBy []struct {
			User struct {
				Name string `json:"name"`
			} `json:"user"`
		} `json:"approved_by"`
	}
	if _, err := g.do(ctx, c, http.MethodGet, fmt.Sprintf("%s/merge_requests/%d/approvals", pp, id), nil, &ap, 1<<20); err != nil {
		return "", err
	}
	var approvers []string
	for _, a := range ap.ApprovedBy {
		approvers = append(approvers, a.User.Name)
	}
	fmt.Fprintf(&sb, "\napprovals (%d): %s", len(approvers), strings.Join(approvers, ", "))
	files, more, err := g.diffs(ctx, c, pp, id, 5)
	if err != nil {
		return "", err
	}
	sb.WriteString("\nfiles:")
	for _, f := range files {
		status, path := "modified", f.NewPath
		switch {
		case f.New:
			status = "added"
		case f.Deleted:
			status, path = "removed", f.OldPath
		case f.Renamed:
			status = "renamed"
		}
		var added, removed int
		for _, l := range strings.Split(f.Diff, "\n") {
			if strings.HasPrefix(l, "+") {
				added++
			} else if strings.HasPrefix(l, "-") {
				removed++
			}
		}
		fmt.Fprintf(&sb, "\n  %s %s +%d -%d", status, path, added, removed)
	}
	if more {
		sb.WriteString("\n  (more files not listed)")
	}
	if m.Description != "" {
		sb.WriteString("\ndescription:\n")
		sb.WriteString(m.Description)
	}
	return sb.String(), nil
}

func (g *GitLab) mrDiff(ctx context.Context, c tools.Creds, project string, id int) (string, error) {
	pp, err := projectPath(project)
	if err != nil {
		return "", err
	}
	if id <= 0 {
		return "", errors.New("id is required")
	}
	files, more, err := g.diffs(ctx, c, pp, id, 5)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, f := range files {
		from, to := "a/"+f.OldPath, "b/"+f.NewPath
		fmt.Fprintf(&sb, "diff --git %s %s\n", from, to)
		if f.New {
			from = "/dev/null"
		}
		if f.Deleted {
			to = "/dev/null"
		}
		fmt.Fprintf(&sb, "--- %s\n+++ %s\n%s", from, to, f.Diff)
		if f.Diff == "" {
			sb.WriteString("(no text diff: binary, too large or only renamed)\n")
		} else if !strings.HasSuffix(f.Diff, "\n") {
			sb.WriteByte('\n')
		}
		if sb.Len() > tools.MaxOutput {
			more = true
			break
		}
	}
	out := sb.String()
	if len(out) > tools.MaxOutput {
		out = out[:tools.MaxOutput-200]
	}
	if more {
		out += "\n... diff truncated; use gitlab_mr_get for the file list"
	}
	if out == "" {
		return "empty diff", nil
	}
	return out, nil
}

// sameCommit compares a full or short hash with the merge request's head.
func sameCommit(expected, actual string) bool {
	expected, actual = strings.ToLower(strings.TrimSpace(expected)), strings.ToLower(actual)
	if len(expected) < 12 || len(actual) < 12 {
		return false
	}
	return strings.HasPrefix(expected, actual) || strings.HasPrefix(actual, expected)
}

func (g *GitLab) mergeMR(ctx context.Context, c tools.Creds, project string, id int, expected, strategy string, closeSource bool) (string, error) {
	pp, err := projectPath(project)
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
		return "", errors.New("expected_source_commit is required (at least 12 hex characters, from gitlab_mr_get)")
	}
	m, err := g.getMR(ctx, c, pp, id)
	if err != nil {
		return "", err
	}
	if m.State != "opened" {
		return "", fmt.Errorf("refused: MR !%d is %s", id, m.State)
	}
	main, err := g.defaultBranch(ctx, c, pp)
	if err != nil {
		return "", err
	}
	if m.TargetBranch != main {
		return "", fmt.Errorf("refused: MR !%d targets %q, not the default branch %q", id, m.TargetBranch, main)
	}
	if !sameCommit(expected, m.SHA) {
		return "", fmt.Errorf("refused: MR !%d head is now %s, not the reviewed %s; review again", id, m.SHA, expected)
	}
	// GitLab refuses the merge itself when the head is no longer this sha, so a
	// push that lands after the check above is not merged.
	body := map[string]any{"sha": m.SHA, "squash": strategy == "squash", "should_remove_source_branch": closeSource}
	var merged mergeRequest
	if _, err := g.do(ctx, c, http.MethodPut, fmt.Sprintf("%s/merge_requests/%d/merge", pp, id), body, &merged, 1<<20); err != nil {
		return "", err
	}
	if merged.State != "merged" {
		return "merge accepted, not finished yet; check gitlab_mr_get:\n" + merged.summary(), nil
	}
	return "merged:\n" + merged.summary(), nil
}

func (g *GitLab) comment(ctx context.Context, c tools.Creds, project string, id int, text string) (string, error) {
	pp, err := projectPath(project)
	if err != nil {
		return "", err
	}
	if id <= 0 || strings.TrimSpace(text) == "" {
		return "", errors.New("id and text are required")
	}
	var r struct {
		ID int `json:"id"`
	}
	if _, err := g.do(ctx, c, http.MethodPost, fmt.Sprintf("%s/merge_requests/%d/notes", pp, id), map[string]string{"body": text}, &r, 1<<20); err != nil {
		return "", err
	}
	return fmt.Sprintf("comment %d added to MR !%d", r.ID, id), nil
}

func (g *GitLab) Tools() []tools.Tool {
	type mrArgs struct {
		Project           string `json:"project"`
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
	parse := func(raw json.RawMessage) (mrArgs, error) {
		var a mrArgs
		return a, tools.Args(raw, &a)
	}
	project := tools.Str(`project as its full path, e.g. "group/app" or "group/team/app"`)
	id := tools.Int("merge request number (the N in !N)")
	return []tools.Tool{
		{
			Name: "gitlab_mr_create",
			Description: "Open a merge request from a branch into the project's default branch. MUTATING. " +
				"Idempotent: if an open MR from that branch already exists it is returned instead. Returns the number, URL and source commit.",
			Schema: tools.Object(map[string]any{
				"project": project, "source_branch": tools.Str("branch to merge from, e.g. fix/login-timeout"),
				"title": tools.Str("MR title"), "description": tools.Str("MR description (markdown)"),
				"destination": tools.Str("target branch; must be the default branch (default)"),
			}, "project", "source_branch", "title"),
			Destructive: true,
			Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
				a, err := parse(raw)
				if err != nil {
					return "", err
				}
				return g.createMR(ctx, c, a.Project, a.SourceBranch, a.Destination, a.Title, a.Description)
			},
		},
		{
			Name:        "gitlab_mr_get",
			Description: "Read a merge request (read-only): state, branches, source commit hash (pass it to gitlab_mr_merge), approvals, changed files and description.",
			Schema:      tools.Object(map[string]any{"project": project, "id": id}, "project", "id"),
			Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
				a, err := parse(raw)
				if err != nil {
					return "", err
				}
				return g.mrInfo(ctx, c, a.Project, a.ID)
			},
		},
		{
			Name:        "gitlab_mr_diff",
			Description: "Read a merge request's unified diff (read-only), truncated at 100KB.",
			Schema:      tools.Object(map[string]any{"project": project, "id": id}, "project", "id"),
			Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
				a, err := parse(raw)
				if err != nil {
					return "", err
				}
				return g.mrDiff(ctx, c, a.Project, a.ID)
			},
		},
		{
			Name: "gitlab_mr_merge",
			Description: "Merge a merge request into the default branch. MUTATING and irreversible: get the human's explicit go-ahead first. " +
				"Refused unless the MR is open, targets the default branch, and its head is still expected_source_commit (the commit that was reviewed).",
			Schema: tools.Object(map[string]any{
				"project": project, "id": id,
				"expected_source_commit": tools.Str("source commit hash that was reviewed (from gitlab_mr_get)"),
				"strategy":               tools.Str("merge_commit (default, the project's own merge method) or squash"),
				"close_source_branch":    map[string]any{"type": "boolean", "description": "delete the source branch after merging (default false)"},
			}, "project", "id", "expected_source_commit"),
			Destructive: true,
			Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
				a, err := parse(raw)
				if err != nil {
					return "", err
				}
				return g.mergeMR(ctx, c, a.Project, a.ID, a.ExpectedCommit, a.Strategy, a.CloseSourceBranch)
			},
		},
		{
			Name:        "gitlab_mr_comment",
			Description: "Add a comment to a merge request. MUTATING (visible to the team).",
			Schema:      tools.Object(map[string]any{"project": project, "id": id, "text": tools.Str("comment text (markdown)")}, "project", "id", "text"),
			Destructive: true,
			Run: func(ctx context.Context, c tools.Creds, raw json.RawMessage) (string, error) {
				a, err := parse(raw)
				if err != nil {
					return "", err
				}
				return g.comment(ctx, c, a.Project, a.ID, a.Text)
			},
		},
	}
}
