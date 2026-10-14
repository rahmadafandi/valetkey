package argocd

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/rahmadafandi/valetkey/internal/tools"
)

func (a *ArgoCD) ScopeKey() string { return "argocd" }

// ParseScope reads application names such as "web" or ["web","api"].
func (a *ArgoCD) ParseScope(raw json.RawMessage) (any, error) { return tools.StringOrList(raw) }

func (a *ArgoCD) CheckScope(scope any, tool string, args json.RawMessage) error {
	allowed := scope.([]string)
	var x struct {
		App string `json:"app"`
	}
	json.Unmarshal(args, &x)
	if !slices.Contains(allowed, x.App) {
		return tools.Refuse("%s: app %q is outside this token's scope; it allows %s", tool, x.App, strings.Join(allowed, ", "))
	}
	return nil
}
