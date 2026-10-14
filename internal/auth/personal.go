package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/rahmadafandi/valetkey/internal/store"
	"github.com/rahmadafandi/valetkey/internal/tools"
)

// PersonalTokenPrefix marks a personal access token, so /mcp can tell it from an OAuth access token.
const PersonalTokenPrefix = "vk_"

// CreatePersonalToken stores a new token for userID and returns it; only its hash is kept.
// A zero ttl means the token never expires.
func (s *Server) CreatePersonalToken(ctx context.Context, userID, name string, toolNames []string, scope []byte, ttl time.Duration) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("name is required")
	}
	if len(toolNames) == 0 {
		return "", errors.New("pick at least one tool")
	}
	if _, err := tools.ParseScope(scope); err != nil {
		return "", err
	}
	if len(strings.TrimSpace(string(scope))) == 0 {
		scope = []byte("{}")
	}
	t := store.PersonalToken{UserID: userID, Name: name, Tools: toolNames, Scope: scope}
	if ttl > 0 {
		exp := time.Now().Add(ttl)
		t.ExpiresAt = &exp
	}
	token := PersonalTokenPrefix + rand.Text() + rand.Text()
	if _, err := s.Store.CreatePersonalToken(ctx, t, hash(token)); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Server) verifyPersonal(ctx context.Context, token string) (*mcpauth.TokenInfo, error) {
	p, u, err := s.Store.UsePersonalToken(ctx, hash(token))
	if errors.Is(err, store.ErrNotFound) {
		return nil, mcpauth.ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}
	scope, err := tools.ParseScope(p.Scope)
	if err != nil {
		return nil, fmt.Errorf("personal token %s: %w", p.ID, err)
	}
	// The SDK needs an expiry; a token without one is re-checked on every request anyway.
	exp := time.Now().Add(time.Hour)
	if p.ExpiresAt != nil {
		exp = *p.ExpiresAt
	}
	return &mcpauth.TokenInfo{UserID: u.ID, Expiration: exp, Extra: map[string]any{
		"email":              u.Email,
		tools.RestrictionKey: &tools.Restriction{Name: p.Name, Tools: p.Tools, Scope: scope},
	}}, nil
}
