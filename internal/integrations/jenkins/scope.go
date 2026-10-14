package jenkins

import (
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"

	"github.com/rahmadafandi/valetkey/internal/tools"
)

func (j *Jenkins) ScopeKey() string { return "jenkins" }

// ParseScope reads job paths such as "deploy-web" or "folder/deploy-web".
func (j *Jenkins) ParseScope(raw json.RawMessage) (any, error) {
	jobs, err := tools.StringOrList(raw)
	if err != nil {
		return nil, err
	}
	for i, job := range jobs {
		job = strings.Trim(job, "/")
		if job == "" || strings.Contains(job, "/job/") || strings.HasPrefix(job, "job/") || strings.Contains(job, "://") {
			return nil, errors.New(`jobs are paths such as "deploy-web" or "folder/deploy-web", not URLs`)
		}
		jobs[i] = job
	}
	return jobs, nil
}

func (j *Jenkins) CheckScope(scope any, tool string, args json.RawMessage) error {
	allowed := scope.([]string)
	var a struct {
		JobURL string `json:"jobURL"`
	}
	json.Unmarshal(args, &a)
	job, ok := jobPath(a.JobURL)
	if !ok {
		return tools.Refuse("%s: jobURL %q names no Jenkins job; this token allows %s", tool, a.JobURL, strings.Join(allowed, ", "))
	}
	if !slices.Contains(allowed, job) {
		return tools.Refuse("%s: job %q is outside this token's scope; it allows %s", tool, job, strings.Join(allowed, ", "))
	}
	return nil
}

// jobPath is the job path in a Jenkins job URL: everything from the first
// "job" segment on must be job/<name> pairs. Dot segments, path parameters
// (";") and encoded slashes are refused because Jenkins would resolve them
// to a different job than the one checked here.
func jobPath(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	parts := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	first := slices.Index(parts, "job")
	if first < 0 || (len(parts)-first)%2 != 0 {
		return "", false
	}
	var names []string
	for i, p := range parts {
		seg, err := url.PathUnescape(p)
		if err != nil || seg == "." || seg == ".." || strings.ContainsAny(seg, `;/\`) {
			return "", false
		}
		if i < first {
			continue
		}
		if (i-first)%2 == 0 {
			if seg != "job" {
				return "", false
			}
			continue
		}
		if seg == "" {
			return "", false
		}
		names = append(names, seg)
	}
	return strings.Join(names, "/"), true
}
