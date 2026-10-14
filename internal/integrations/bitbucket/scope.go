package bitbucket

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/rahmadafandi/valetkey/internal/tools"
)

func (b *Bitbucket) ScopeKey() string { return "bitbucket" }

// ParseScope reads one repository as "workspace/slug".
func (b *Bitbucket) ParseScope(raw json.RawMessage) (any, error) {
	var repo string
	if err := json.Unmarshal(raw, &repo); err != nil {
		return nil, errors.New(`expected one repository string such as "acme/web"`)
	}
	repo = strings.TrimSpace(repo)
	if _, err := repoPath(repo); err != nil {
		return nil, errors.New(`expected one repository as "workspace/slug", e.g. "acme/web"`)
	}
	return repo, nil
}

func (b *Bitbucket) CheckScope(scope any, tool string, args json.RawMessage) error {
	allowed := scope.(string)
	var a struct {
		Repo string `json:"repo"`
	}
	json.Unmarshal(args, &a)
	if a.Repo != allowed {
		return tools.Refuse("%s: repository %q is outside this token's scope; it allows %s", tool, a.Repo, allowed)
	}
	return nil
}
