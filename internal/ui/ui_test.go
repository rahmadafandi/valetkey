package ui

import (
	"regexp"
	"strings"
	"testing"
)

// Each outcome the activity page can show needs its own colour rule.
func TestEveryOutcomeHasAColourRule(t *testing.T) {
	css := string(Head)
	css = css[strings.Index(css, "<style>"):strings.Index(css, "</style>")]
	selectors := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)(?:^|\})\s*([^{}]+)\{`).FindAllStringSubmatch(css, -1) {
		for _, s := range strings.Split(m[1], ",") {
			selectors[strings.TrimSpace(s)] = true
		}
	}
	for _, outcome := range []string{"ok", "error", "refused", "dry_run"} {
		if !selectors[".outcome."+outcome] {
			t.Errorf("no rule for .outcome.%s", outcome)
		}
	}
}
