package main

import (
	"context"
	"log/slog"
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rahmadafandi/valetkey/internal/config"
	"github.com/rahmadafandi/valetkey/internal/tools"
)

func nativeIntegrations(t *testing.T) []tools.Integration {
	t.Helper()
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
	return ints
}

// Every integration must be fenceable by a token's scope, destructive tools above all.
func TestIntegrationsAreScoped(t *testing.T) {
	for _, in := range nativeIntegrations(t) {
		if _, ok := in.(tools.Scoper); !ok {
			t.Errorf("%s does not implement tools.Scoper", in.System())
		}
		for _, tl := range in.Tools() {
			if tl.Unscoped {
				t.Errorf("%s: native tool is Unscoped, so a token's scope would not fence it", tl.Name)
			}
		}
	}
}

// NewServer skips a tool the SDK refuses, so a broken native tool would vanish
// quietly; every one must actually be listed.
func TestEveryNativeToolIsServed(t *testing.T) {
	ints := nativeIntegrations(t)
	srv := tools.NewServer(ints, nil, "https://valetkey.test", slog.New(slog.DiscardHandler), nil, nil)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(context.Background(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	var listed []string
	for tl, err := range cs.Tools(context.Background(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		listed = append(listed, tl.Name)
	}
	for _, in := range ints {
		for _, tl := range in.Tools() {
			if !slices.Contains(listed, tl.Name) {
				t.Errorf("%s is not listed by the MCP server", tl.Name)
			}
		}
	}
}
