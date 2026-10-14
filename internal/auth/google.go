package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// googleEmail exchanges a Google authorization code and returns the account's
// lowercased email after checking issuer, audience, verification and domain.
// The ID token comes straight from Google's token endpoint over TLS, so per
// OIDC Core 3.1.3.7 its signature check may be skipped.
func (s *Server) googleEmail(ctx context.Context, code string) (string, error) {
	tok, err := s.Google.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("google token exchange failed: %w", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", errors.New("google returned no ID token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("google returned an unreadable ID token")
	}
	var c struct {
		Iss           string `json:"iss"`
		Aud           string `json:"aud"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		HD            string `json:"hd"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", errors.New("google returned an unreadable ID token")
	}
	if c.Aud != s.Google.ClientID || (c.Iss != "https://accounts.google.com" && c.Iss != "accounts.google.com") {
		return "", errors.New("ID token was not issued for this app")
	}
	if !c.EmailVerified {
		return "", errors.New("google account email is not verified")
	}
	email := strings.ToLower(strings.TrimSpace(c.Email))
	at := strings.LastIndex(email, "@")
	if at < 1 || !slices.Contains(s.AllowedDomains, email[at+1:]) {
		return "", fmt.Errorf("account %s is not on an allowed domain", email)
	}
	// hd is set only for Google Workspace accounts, so a consumer address cannot pass.
	if strings.ToLower(c.HD) != email[at+1:] {
		return "", fmt.Errorf("account %s is not a Workspace account of an allowed domain", email)
	}
	return email, nil
}
