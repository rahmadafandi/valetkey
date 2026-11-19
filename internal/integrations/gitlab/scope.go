package gitlab

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/rahmadafandi/valetkey/internal/tools"
)

func (g *GitLab) ScopeKey() string { return "gitlab" }

// ParseScope reads one project as its full path, such as "group/app", or a list of them.
func (g *GitLab) ParseScope(raw json.RawMessage) (any, error) {
	projects, err := tools.StringOrList(raw)
	if err != nil {
		return nil, errors.New(`expected a project path such as "group/app", or a list of them`)
	}
	for _, p := range projects {
		if _, err := projectPath(p); err != nil {
			return nil, fmt.Errorf(`expected each project as its full path, e.g. "group/app" or "group/team/app"; got %q`, p)
		}
	}
	return projects, nil
}

// CheckScope compares the path exactly as written. GitLab reads paths without
// regard to case, so a call that spells an allowed project differently is refused.
func (g *GitLab) CheckScope(scope any, tool string, args json.RawMessage) error {
	allowed := scope.([]string)
	var a struct {
		Project string `json:"project"`
	}
	json.Unmarshal(args, &a)
	if !slices.Contains(allowed, a.Project) {
		return tools.Refuse("%s: project %q is outside this token's scope; it allows %s", tool, a.Project, strings.Join(allowed, ", "))
	}
	return nil
}
