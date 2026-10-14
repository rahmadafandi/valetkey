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

// NewToken is what a person asks for when creating a personal access token.
type NewToken struct {
	Name             string
	Tools            []string
	Scope            []byte
	TTL              time.Duration // 0 means it never expires
	MaxWritesPerHour int           // 0 means unlimited
	DryRun           bool
}

// CreatePersonalToken stores a new token for userID and returns it; only its hash is kept.
func (s *Server) CreatePersonalToken(ctx context.Context, userID string, n NewToken) (string, error) {
	name, toolNames, scope, ttl := strings.TrimSpace(n.Name), n.Tools, n.Scope, n.TTL
	if name == "" {
		return "", errors.New("name is required")
	}
	if len(toolNames) == 0 {
		return "", errors.New("pick at least one tool")
	}
	if n.MaxWritesPerHour < 0 {
		return "", errors.New("write limit cannot be negative")
	}
	if _, err := tools.ParseScope(s.Integrations, scope); err != nil {
		return "", err
	}
	if len(strings.TrimSpace(string(scope))) == 0 {
		scope = []byte("{}")
	}
	t := store.PersonalToken{UserID: userID, Name: name, Tools: toolNames, Scope: scope,
		MaxWritesPerHour: n.MaxWritesPerHour, DryRun: n.DryRun}
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
	scope, err := tools.ParseScope(s.Integrations, p.Scope)
	if err != nil {
		return nil, fmt.Errorf("personal token %s: %w", p.ID, err)
	}
	// The SDK needs an expiry; a token without one is re-checked on every request anyway.
	exp := time.Now().Add(time.Hour)
	if p.ExpiresAt != nil {
		exp = *p.ExpiresAt
	}
	return &mcpauth.TokenInfo{UserID: u.ID, Expiration: exp, Extra: map[string]any{
		"email": u.Email,
		tools.RestrictionKey: &tools.Restriction{TokenID: p.ID, Name: p.Name, Tools: p.Tools, Scope: scope,
			MaxWritesPerHour: p.MaxWritesPerHour, DryRun: p.DryRun},
	}}, nil
}
