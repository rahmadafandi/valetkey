package auth

import (
	"context"
	"crypto/rand"
	"errors"
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

// personalToken checks what a token is given, as on create and on edit.
func (s *Server) personalToken(userID string, n NewToken) (store.PersonalToken, error) {
	name, scope := strings.TrimSpace(n.Name), n.Scope
	if name == "" {
		return store.PersonalToken{}, errors.New("name is required")
	}
	if len(n.Tools) == 0 {
		return store.PersonalToken{}, errors.New("pick at least one tool")
	}
	if n.MaxWritesPerHour < 0 {
		return store.PersonalToken{}, errors.New("write limit cannot be negative")
	}
	if _, err := tools.ParseScope(s.Integrations, scope); err != nil {
		return store.PersonalToken{}, err
	}
	if len(strings.TrimSpace(string(scope))) == 0 {
		scope = []byte("{}")
	}
	return store.PersonalToken{UserID: userID, Name: name, Tools: n.Tools, Scope: scope,
		MaxWritesPerHour: n.MaxWritesPerHour, DryRun: n.DryRun}, nil
}

// UpdatePersonalToken changes what one of the user's tokens may do; n.TTL is
// ignored. Every call reads the token afresh, so the change applies from its
// next call.
func (s *Server) UpdatePersonalToken(ctx context.Context, userID, id string, n NewToken) error {
	t, err := s.personalToken(userID, n)
	if err != nil {
		return err
	}
	t.ID = id
	return s.Store.UpdatePersonalToken(ctx, t)
}

// CreatePersonalToken stores a new token for userID and returns it; only its hash is kept.
func (s *Server) CreatePersonalToken(ctx context.Context, userID string, n NewToken) (string, error) {
	t, err := s.personalToken(userID, n)
	if err != nil {
		return "", err
	}
	if n.TTL > 0 {
		exp := time.Now().Add(n.TTL)
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
		s.Log.Error("verify personal token", "err", err)
		return nil, errVerify
	}
	scope, err := tools.ParseScope(s.Integrations, p.Scope)
	if err != nil {
		// Usually its scope names an integration that has since been turned off.
		s.Log.Warn("personal token refused", "token", p.ID, "reason", err)
		return nil, mcpauth.ErrInvalidToken
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
