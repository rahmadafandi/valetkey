package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/rahmadafandi/valetkey/internal/tools"
)

func TestPersonalToken(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	u, _ := e.as.Store.UpsertUser(ctx, "rahmad@example.com")
	scope := []byte(`{"bitbucket":"acme/web","jenkins":["deploy-web"]}`)
	tok, err := e.as.CreatePersonalToken(ctx, u.ID, NewToken{Name: "atlas", Tools: []string{"jenkins_deploy"}, Scope: scope})
	if err != nil || !strings.HasPrefix(tok, PersonalTokenPrefix) {
		t.Fatalf("create: %q %v", tok, err)
	}
	ti, err := e.as.Verify(ctx, tok, nil)
	if err != nil || ti.UserID != u.ID || ti.Extra["email"] != "rahmad@example.com" || ti.Expiration.IsZero() {
		t.Fatalf("verify: %+v %v", ti, err)
	}
	r := tools.RestrictionOf(ti)
	if r == nil || r.Name != "atlas" || !r.Allows("jenkins_deploy") || r.Allows("jenkins_rebuild") || r.Scope["bitbucket"] != "acme/web" {
		t.Fatalf("restriction: %+v", r)
	}

	if _, err := e.as.Verify(ctx, PersonalTokenPrefix+"forged", nil); !errors.Is(err, mcpauth.ErrInvalidToken) {
		t.Errorf("forged token: %v", err)
	}
	list, _ := e.as.Store.ListPersonalTokens(ctx, u.ID)
	if err := e.as.Store.DeletePersonalToken(ctx, u.ID, list[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.as.Verify(ctx, tok, nil); !errors.Is(err, mcpauth.ErrInvalidToken) {
		t.Errorf("revoked token: %v", err)
	}
}

func TestPersonalTokenExpiry(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	u, _ := e.as.Store.UpsertUser(ctx, "rahmad@example.com")
	tok, err := e.as.CreatePersonalToken(ctx, u.ID, NewToken{Name: "short", Tools: []string{"loki_query"}, TTL: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ti, err := e.as.Verify(ctx, tok, nil)
	if err != nil || ti.Expiration.Before(time.Now().Add(29*24*time.Hour)) {
		t.Fatalf("expiry: %+v %v", ti, err)
	}
}

func TestCreatePersonalTokenValidates(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	u, _ := e.as.Store.UpsertUser(ctx, "rahmad@example.com")
	for name, c := range map[string]struct {
		name  string
		tools []string
		scope string
	}{
		"no name":   {" ", []string{"loki_query"}, `{}`},
		"no tools":  {"x", nil, `{}`},
		"bad scope": {"x", []string{"loki_query"}, `{"jenkin":"a"}`},
	} {
		if _, err := e.as.CreatePersonalToken(ctx, u.ID, NewToken{Name: c.name, Tools: c.tools, Scope: []byte(c.scope)}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
