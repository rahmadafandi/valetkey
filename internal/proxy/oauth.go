package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"

	"github.com/rahmadafandi/valetkey/internal/store"
	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/upstream"
)

// ErrNeedClient means the authorization server offers no dynamic registration,
// so the user has to supply a client ID and secret.
var ErrNeedClient = errors.New("this authorization server does not register clients itself: enter a client ID and secret")

// NeedClientError is ErrNeedClient naming the authorization server, so the
// user knows who receives the client secret.
type NeedClientError struct{ Host string }

func (e *NeedClientError) Error() string        { return ErrNeedClient.Error() }
func (e *NeedClientError) Is(target error) bool { return target == ErrNeedClient }

// pendingSystem holds a sign-in in progress apart from the working login,
// so an abandoned reconnect leaves that login in place.
func pendingSystem(upstreamID string) string { return CredsSystem(upstreamID) + "/pending" }

// refreshMargin is how close to expiry an access token is refreshed before use.
const refreshMargin = 30 * time.Second

// StartOAuth finds the upstream's authorization server, registers valetkey when
// clientID is empty, stores a pending credential holding the PKCE verifier and
// client, and returns the URL to send the user's browser to.
func (p *Proxy) StartOAuth(ctx context.Context, userID string, u store.Upstream, clientID, clientSecret, state string) (string, error) {
	as, err := p.discover(ctx, u)
	if err != nil {
		return "", fmt.Errorf("%s: %w", u.Name, err)
	}
	redirect := p.PublicURL + "/upstreams/" + u.ID + "/callback"
	if clientID == "" {
		if as.RegistrationEndpoint == "" {
			host := as.Issuer
			if iu, err := url.Parse(as.Issuer); err == nil && iu.Host != "" {
				host = iu.Host
			}
			return "", &NeedClientError{Host: host}
		}
		rctx, cancel := context.WithTimeout(ctx, connectTimeout)
		defer cancel()
		reg, err := oauthex.RegisterClient(rctx, as.RegistrationEndpoint, &oauthex.ClientRegistrationMetadata{
			ClientName:              "valetkey",
			RedirectURIs:            []string{redirect},
			TokenEndpointAuthMethod: "none",
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			ResponseTypes:           []string{"code"},
		}, p.Guard.Client())
		if err != nil {
			return "", fmt.Errorf("%s: %w", u.Name, err)
		}
		clientID, clientSecret = reg.ClientID, reg.ClientSecret
	}
	verifier := oauth2.GenerateVerifier()
	c := tools.Creds{
		"pending": "1", "verifier": verifier,
		"client_id": clientID, "client_secret": clientSecret, "token_auth": tokenAuth(clientSecret, as.TokenEndpointAuthMethodsSupported),
		"token_endpoint": as.TokenEndpoint, "resource": u.URL, "redirect_uri": redirect,
	}
	if err := p.Creds.Save(ctx, userID, pendingSystem(u.ID), c); err != nil {
		return "", err
	}
	cfg := oauthConfig(c)
	cfg.Endpoint.AuthURL = as.AuthorizationEndpoint
	return cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("resource", u.URL)), nil
}

// FinishOAuth exchanges the code from the callback for tokens, stores them as
// the upstream's login and drops the pending sign-in.
func (p *Proxy) FinishOAuth(ctx context.Context, userID string, u store.Upstream, code string) error {
	c, err := p.Creds.Load(ctx, userID, pendingSystem(u.ID))
	if errors.Is(err, tools.ErrNotConnected) || err == nil && c["pending"] != "1" {
		return fmt.Errorf("%s: no sign-in is in progress", u.Name)
	}
	if err != nil {
		return err
	}
	tctx, cancel := p.tokenContext(ctx)
	defer cancel()
	tok, err := oauthConfig(c).Exchange(tctx, code, oauth2.VerifierOption(c["verifier"]), oauth2.SetAuthURLParam("resource", c["resource"]))
	if err != nil {
		return fmt.Errorf("%s: %w", u.Name, err)
	}
	if err := p.Creds.Save(ctx, userID, CredsSystem(u.ID), tokenCreds(c, tok)); err != nil {
		return err
	}
	return p.Creds.Delete(ctx, userID, pendingSystem(u.ID))
}

// Login loads the user's working login for the upstream, refreshing an OAuth
// access token that is about to expire. An upstream without a login gets empty creds.
func (p *Proxy) Login(ctx context.Context, userID string, u store.Upstream) (tools.Creds, error) {
	if u.Auth == "none" {
		return tools.Creds{}, nil
	}
	c, err := p.Creds.Load(ctx, userID, CredsSystem(u.ID))
	if err != nil {
		return nil, err
	}
	if u.Auth == "oauth" && expiring(c) {
		return p.refresh(ctx, userID, u, c["access_token"])
	}
	return c, nil
}

// tokenAuth picks how a client authenticates at the token endpoint: "none" for
// a public client, else client_secret_basic (the RFC 6749 default) unless the
// server lists only client_secret_post.
func tokenAuth(secret string, supported []string) string {
	switch {
	case secret == "":
		return "none"
	case !slices.Contains(supported, "client_secret_basic") && slices.Contains(supported, "client_secret_post"):
		return "post"
	}
	return "basic"
}

// discover follows the upstream's protected-resource metadata to its
// authorization server's metadata. Every fetch goes through the guard.
func (p *Proxy) discover(ctx context.Context, u store.Upstream) (*oauthex.AuthServerMeta, error) {
	endpoint, err := p.Guard.CheckURL(u.URL)
	if err != nil {
		return nil, err
	}
	locations := wellKnown(endpoint, "oauth-protected-resource", false)
	if m := p.resourceMetadataURL(ctx, u.URL); m != "" {
		locations = []string{m}
	}
	var prm oauthex.ProtectedResourceMetadata
	if err := p.firstJSON(ctx, locations, &prm); err != nil {
		return nil, fmt.Errorf("protected-resource metadata: %w", err)
	}
	if !resourceMatches(prm.Resource, endpoint) {
		return nil, fmt.Errorf("protected-resource metadata is for %q, not this server", prm.Resource)
	}
	if len(prm.AuthorizationServers) == 0 {
		return nil, errors.New("protected-resource metadata names no authorization server")
	}
	issuer, err := p.Guard.CheckURL(prm.AuthorizationServers[0])
	if err != nil {
		return nil, fmt.Errorf("authorization server: %w", err)
	}
	var as oauthex.AuthServerMeta
	if err := p.firstJSON(ctx, wellKnown(issuer, "oauth-authorization-server", true), &as); err != nil {
		return nil, fmt.Errorf("authorization server metadata: %w", err)
	}
	if strings.TrimSuffix(as.Issuer, "/") != strings.TrimSuffix(prm.AuthorizationServers[0], "/") {
		return nil, fmt.Errorf("authorization server metadata names issuer %q, not %q", as.Issuer, prm.AuthorizationServers[0])
	}
	if !slices.Contains(as.CodeChallengeMethodsSupported, "S256") {
		return nil, errors.New("the authorization server does not support PKCE with S256")
	}
	if as.AuthorizationEndpoint == "" || as.TokenEndpoint == "" {
		return nil, errors.New("authorization server metadata lacks an authorization or token endpoint")
	}
	// The authorization endpoint is only a browser redirect; the others are fetched, and the guard checks them again when dialing.
	for name, raw := range map[string]string{"authorization_endpoint": as.AuthorizationEndpoint, "token_endpoint": as.TokenEndpoint, "registration_endpoint": as.RegistrationEndpoint} {
		if raw == "" {
			continue
		}
		if _, err := p.Guard.CheckURL(raw); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	return &as, nil
}

// resourceMetadataURL is the metadata's resource value: required (RFC 9728
// section 3.3) and either the MCP URL itself or its origin, both canonical
// server URIs in the MCP authorization spec. Scheme, host and a trailing slash
// are compared loosely.
func resourceMatches(resource string, endpoint *url.URL) bool {
	r, err := url.Parse(resource)
	if resource == "" || err != nil || !sameOrigin(r, endpoint) || r.RawQuery != "" || r.Fragment != "" {
		return false
	}
	path := strings.TrimSuffix(r.Path, "/")
	return path == "" || path == strings.TrimSuffix(endpoint.Path, "/")
}

// resourceMetadataURL asks the upstream without credentials and reads
// resource_metadata from the 401's WWW-Authenticate header, or returns "".
func (p *Proxy) resourceMetadataURL(ctx context.Context, endpoint string) string {
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := p.Guard.Client().Do(req)
	if err != nil {
		return ""
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		return ""
	}
	challenges, err := oauthex.ParseWWWAuthenticate(resp.Header.Values("WWW-Authenticate"))
	if err != nil {
		return ""
	}
	for _, c := range challenges {
		if m := c.Params["resource_metadata"]; m != "" {
			return m
		}
	}
	return ""
}

// wellKnown lists where RFC 8414 and RFC 9728 put a metadata document for u,
// most specific first; withOIDC adds the OpenID Connect locations.
func wellKnown(u *url.URL, name string, withOIDC bool) []string {
	at := func(path string) string { return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: path}).String() }
	path := strings.Trim(u.Path, "/")
	var out []string
	if path != "" {
		out = append(out, at("/.well-known/"+name+"/"+path))
		if withOIDC {
			out = append(out, at("/.well-known/openid-configuration/"+path), at("/"+path+"/.well-known/openid-configuration"))
		}
	}
	out = append(out, at("/.well-known/"+name))
	if withOIDC {
		out = append(out, at("/.well-known/openid-configuration"))
	}
	return out
}

// firstJSON decodes the first location that answers 200. A 4xx moves on to the
// next location; any other failure, such as the guard refusing the address, stops.
func (p *Proxy) firstJSON(ctx context.Context, locations []string, v any) error {
	for _, loc := range locations {
		found, err := p.getJSON(ctx, loc, v)
		if err != nil || found {
			return err
		}
	}
	return fmt.Errorf("not found at %s", strings.Join(locations, ", "))
}

func (p *Proxy) getJSON(ctx context.Context, loc string, v any) (found bool, err error) {
	if _, err := p.Guard.CheckURL(loc); err != nil {
		return false, fmt.Errorf("%s: %w", loc, err)
	}
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loc, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.Guard.Client().Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return false, nil
	case resp.StatusCode != http.StatusOK:
		return false, fmt.Errorf("%s: status %d", loc, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return false, fmt.Errorf("%s: %w", loc, err)
	}
	return true, nil
}

func oauthConfig(c tools.Creds) *oauth2.Config {
	style := oauth2.AuthStyleInParams
	if c["token_auth"] == "basic" {
		style = oauth2.AuthStyleInHeader
	}
	return &oauth2.Config{
		ClientID:     c["client_id"],
		ClientSecret: c["client_secret"],
		Endpoint:     oauth2.Endpoint{TokenURL: c["token_endpoint"], AuthStyle: style},
		RedirectURL:  c["redirect_uri"],
	}
}

// tokenContext makes oauth2 use the guarded client, under the connect timeout.
func (p *Proxy) tokenContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithValue(ctx, oauth2.HTTPClient, p.Guard.Client()), connectTimeout)
}

func tokenCreds(c tools.Creds, tok *oauth2.Token) tools.Creds {
	out := tools.Creds{
		"access_token": tok.AccessToken, "refresh_token": tok.RefreshToken,
		"client_id": c["client_id"], "client_secret": c["client_secret"], "token_auth": c["token_auth"],
		"token_endpoint": c["token_endpoint"], "resource": c["resource"],
	}
	if !tok.Expiry.IsZero() {
		out["expiry"] = tok.Expiry.UTC().Format(time.RFC3339)
	}
	return out
}

func expiring(c tools.Creds) bool {
	t, err := time.Parse(time.RFC3339, c["expiry"])
	return err == nil && time.Until(t) < refreshMargin
}

var refreshLocks sync.Map // "<user>/<upstream>" -> *sync.Mutex

// refresh trades the stored refresh token for new tokens and saves them for
// the same user and upstream. stale is the access token the caller had: when
// the stored one differs and is fresh, another call already refreshed it.
func (p *Proxy) refresh(ctx context.Context, userID string, u store.Upstream, stale string) (tools.Creds, error) {
	// ponytail: in-process lock, which fits one instance; replicas sharing the
	// database can still both refresh and lose a rotated refresh token.
	l, _ := refreshLocks.LoadOrStore(userID+"/"+u.ID, &sync.Mutex{})
	l.(*sync.Mutex).Lock()
	defer l.(*sync.Mutex).Unlock()

	c, err := p.Creds.Load(ctx, userID, CredsSystem(u.ID))
	if err != nil {
		return nil, err
	}
	if c["pending"] != "" {
		return nil, fmt.Errorf("%s: %w", u.Name, tools.ErrNotConnected)
	}
	if c["access_token"] != stale && !expiring(c) {
		return c, nil
	}
	if c["refresh_token"] == "" {
		return nil, fmt.Errorf("%s: the login expired and cannot be refreshed: %w", u.Name, upstream.ErrUnauthorized)
	}
	tok, err := p.refreshToken(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("%s: refreshing the login: %w", u.Name, err)
	}
	next := tokenCreds(c, tok)
	// The old refresh token may be spent already, so a caller giving up must not stop the save.
	if err := p.Creds.Save(context.WithoutCancel(ctx), userID, CredsSystem(u.ID), next); err != nil {
		return nil, err
	}
	return next, nil
}

// refreshToken posts a refresh_token grant with the resource, which oauth2's
// TokenSource cannot send, authenticating as the code exchange did. A 400 or
// 401 is a rejected login; anything else is an outage.
func (p *Proxy) refreshToken(ctx context.Context, c tools.Creds) (*oauth2.Token, error) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {c["refresh_token"]}, "resource": {c["resource"]}}
	if c["token_auth"] != "basic" {
		form.Set("client_id", c["client_id"])
	}
	if c["token_auth"] == "post" {
		form.Set("client_secret", c["client_secret"])
	}
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c["token_endpoint"], strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c["token_auth"] == "basic" {
		// RFC 6749 section 2.3.1: both halves are form-encoded before Basic encoding.
		req.SetBasicAuth(url.QueryEscape(c["client_id"]), url.QueryEscape(c["client_secret"]))
	}
	resp, err := p.Guard.Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var body struct {
		AccessToken  string      `json:"access_token"`
		RefreshToken string      `json:"refresh_token"`
		ExpiresIn    json.Number `json:"expires_in"`
		Error        string      `json:"error"`
	}
	decodeErr := json.NewDecoder(resp.Body).Decode(&body)
	switch {
	case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized:
		return nil, fmt.Errorf("the authorization server refused it (%d %s): %w", resp.StatusCode, body.Error, upstream.ErrUnauthorized)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("the token endpoint answered %d", resp.StatusCode)
	case decodeErr != nil:
		return nil, decodeErr
	case body.AccessToken == "":
		return nil, errors.New("the token response has no access_token")
	}
	tok := &oauth2.Token{AccessToken: body.AccessToken, RefreshToken: body.RefreshToken}
	if tok.RefreshToken == "" {
		tok.RefreshToken = c["refresh_token"]
	}
	if secs, err := body.ExpiresIn.Int64(); err == nil && secs > 0 {
		tok.Expiry = time.Now().Add(time.Duration(secs) * time.Second)
	}
	return tok, nil
}
