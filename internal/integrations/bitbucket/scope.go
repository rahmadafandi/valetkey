package bitbucket

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/rahmadafandi/valetkey/internal/tools"
)

func (b *Bitbucket) ScopeKey() string { return "bitbucket" }

// ParseScope reads one repository as "workspace/slug", or a list of them.
func (b *Bitbucket) ParseScope(raw json.RawMessage) (any, error) {
	repos, err := tools.StringOrList(raw)
	if err != nil {
		return nil, errors.New(`expected a repository such as "acme/web", or a list of them`)
	}
	for _, r := range repos {
		if _, err := repoPath(r); err != nil {
			return nil, fmt.Errorf(`expected each repository as "workspace/slug", e.g. "acme/web"; got %q`, r)
		}
	}
	return repos, nil
}

func (b *Bitbucket) CheckScope(scope any, tool string, args json.RawMessage) error {
	allowed := scope.([]string)
	var a struct {
		Repo string `json:"repo"`
	}
	json.Unmarshal(args, &a)
	if !slices.Contains(allowed, a.Repo) {
		return tools.Refuse("%s: repository %q is outside this token's scope; it allows %s", tool, a.Repo, strings.Join(allowed, ", "))
	}
	return nil
}
