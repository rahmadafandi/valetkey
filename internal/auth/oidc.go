package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/rahmadafandi/valetkey/internal/version"
	"golang.org/x/oauth2"
)

const googleIssuer = "https://accounts.google.com"

// discoveryClient bounds discovery, which runs at startup before the server listens.
var discoveryClient = &http.Client{Timeout: 15 * time.Second, Transport: version.Transport(nil)}

// OIDC signs people in with any OpenID Connect provider and decides who may enter.
type OIDC struct {
	Issuer               string
	Config               *oauth2.Config
	AllowedDomains       []string // lowercase
	AllowedEmails        []string // lowercase
	TrustUnverifiedEmail bool     // for providers that omit email_verified (Entra ID)
}

// Discover reads the provider's endpoints from its OpenID configuration and
// checks that the document names the same issuer.
func Discover(ctx context.Context, issuer string) (oauth2.Endpoint, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return oauth2.Endpoint{}, err
	}
	resp, err := discoveryClient.Do(req)
	if err != nil {
		return oauth2.Endpoint{}, fmt.Errorf("oidc discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return oauth2.Endpoint{}, fmt.Errorf("oidc discovery: %s answered %d", issuer, resp.StatusCode)
	}
	var d struct {
		Issuer string `json:"issuer"`
		Auth   string `json:"authorization_endpoint"`
		Token  string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return oauth2.Endpoint{}, fmt.Errorf("oidc discovery: %w", err)
	}
	if d.Issuer != issuer {
		return oauth2.Endpoint{}, fmt.Errorf("oidc discovery: document issuer %q does not match OIDC_ISSUER %q", d.Issuer, issuer)
	}
	if d.Auth == "" || d.Token == "" {
		return oauth2.Endpoint{}, errors.New("oidc discovery: endpoints missing")
	}
	return oauth2.Endpoint{AuthURL: d.Auth, TokenURL: d.Token}, nil
}

// Email exchanges an authorization code and returns the account's lowercased
// email once it passes the issuer, audience, verification and allow-list checks.
// The ID token comes straight from the token endpoint over TLS, so per OIDC
// Core 3.1.3.7 its signature check may be skipped.
func (o *OIDC) Email(ctx context.Context, code string) (string, error) {
	tok, err := o.Config.Exchange(context.WithValue(ctx, oauth2.HTTPClient, discoveryClient), code)
	if err != nil {
		return "", fmt.Errorf("token exchange failed: %w", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", errors.New("identity provider returned no ID token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("identity provider returned an unreadable ID token")
	}
	var c struct {
		Iss           string          `json:"iss"`
		Aud           json.RawMessage `json:"aud"`
		Email         string          `json:"email"`
		EmailVerified json.RawMessage `json:"email_verified"`
		HD            string          `json:"hd"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", errors.New("identity provider returned an unreadable ID token")
	}
	// Google documents both forms of its iss claim.
	if c.Iss != o.Issuer && !(o.Issuer == googleIssuer && c.Iss == "accounts.google.com") {
		return "", fmt.Errorf("ID token was issued by %q, not %q", c.Iss, o.Issuer)
	}
	if !audience(c.Aud, o.Config.ClientID) {
		return "", errors.New("ID token was not issued for this app")
	}
	email := strings.ToLower(strings.TrimSpace(c.Email))
	at := strings.LastIndex(email, "@")
	if at < 1 {
		return "", errors.New("identity provider returned no email; request the email scope")
	}
	if v := strings.Trim(string(c.EmailVerified), `"`); v != "true" && !o.TrustUnverifiedEmail {
		return "", fmt.Errorf("email %s is not verified by the identity provider", email)
	}
	domain := email[at+1:]
	if slices.Contains(o.AllowedEmails, email) {
		return email, nil
	}
	if slices.Contains(o.AllowedDomains, domain) {
		// hd is set only for Google Workspace accounts, so a consumer account
		// registered with a company address cannot pass on the domain alone.
		if o.Issuer == googleIssuer && strings.ToLower(c.HD) != domain {
			return "", fmt.Errorf("account %s is not a Workspace account of an allowed domain", email)
		}
		return email, nil
	}
	return "", fmt.Errorf("account %s is not allowed on this server", email)
}

func audience(raw json.RawMessage, clientID string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == clientID
	}
	var many []string
	return json.Unmarshal(raw, &many) == nil && slices.Contains(many, clientID)
}
