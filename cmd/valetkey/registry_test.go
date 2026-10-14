package main

import (
	"testing"

	"github.com/rahmadafandi/valetkey/internal/config"
	"github.com/rahmadafandi/valetkey/internal/tools"
)

// Every integration must be fenceable by a token's scope, destructive tools above all.
func TestIntegrationsAreScoped(t *testing.T) {
	cfg := config.Config{Upstreams: map[string]config.Upstream{}}
	for _, s := range config.Systems {
		cfg.Upstreams[s] = config.Upstream{URL: "https://" + s + ".example.com"}
	}
	ints, err := integrations(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(ints) != len(config.Systems) {
		t.Fatalf("built %d integrations for %d systems", len(ints), len(config.Systems))
	}
	for _, in := range ints {
		if _, ok := in.(tools.Scoper); !ok {
			t.Errorf("%s does not implement tools.Scoper", in.System())
		}
	}
}
