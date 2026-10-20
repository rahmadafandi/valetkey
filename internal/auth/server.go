package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"

	"github.com/rahmadafandi/valetkey/internal/store"
	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/ui"
)

type Server struct {
	Store      *store.Store
	Signer     *Signer
	IdP        *OIDC
	PublicURL  string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	SessionTTL time.Duration // how long a web sign-in lasts
	Log        *slog.Logger
	// Integrations are the enabled upstreams; a personal access token's scope
	// is read against them.
	Integrations []tools.Integration
}

const (
	nonceCookie   = "vk_nonce"
	sessionCookie = "vk_session"
	codeTTL       = 10 * time.Minute
)

// pending is the sign-in request carried through the identity provider inside the signed state.
type pending struct {
	Kind        string `json:"k"` // "mcp" or "web"
	Nonce       string `json:"n"` // must match the nonce cookie of the browser that started
	ClientID    string `json:"c,omitempty"`
	RedirectURI string `json:"r,omitempty"`
	Challenge   string `json:"p,omitempty"`
	State       string `json:"s,omitempty"`
}

type session struct {
	UserID string `json:"u"`
	Email  string `json:"e"`
}

func (s *Server) Routes(mux *http.ServeMux) {
	prm := mcpauth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               s.PublicURL + "/mcp",
		AuthorizationServers:   []string{s.PublicURL},
		BearerMethodsSupported: []string{"header"},
	})
	mux.Handle("/.well-known/oauth-protected-resource", prm)
	mux.Handle("/.well-known/oauth-protected-resource/mcp", prm)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.metadata)
	mux.HandleFunc("POST /oauth/register", s.register)
	mux.HandleFunc("GET /oauth/authorize", s.authorize)
	mux.HandleFunc("GET /oauth/oidc/callback", s.idpCallback)
	mux.HandleFunc("POST /oauth/consent", s.consent)
	mux.HandleFunc("POST /oauth/token", s.token)
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) { s.toIdP(w, r, pending{Kind: "web"}) })
	mux.HandleFunc("GET /logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/", http.StatusFound)
	})
}

func (s *Server) ResourceMetadataURL() string {
	return s.PublicURL + "/.well-known/oauth-protected-resource"
}

// errVerify is what a caller sees when a token cannot be checked; the SDK
// sends a verifier's error text in the 500 response, so details stay in the log.
var errVerify = errors.New("could not check the token (internal error)")

// Verify is the bearer-token check for /mcp.
func (s *Server) Verify(ctx context.Context, token string, _ *http.Request) (*mcpauth.TokenInfo, error) {
	if strings.HasPrefix(token, PersonalTokenPrefix) {
		return s.verifyPersonal(ctx, token)
	}
	t, u, err := s.Store.LookupToken(ctx, hash(token), "access")
	if errors.Is(err, store.ErrNotFound) {
		return nil, mcpauth.ErrInvalidToken
	}
	if err != nil {
		s.Log.Error("verify access token", "err", err)
		return nil, errVerify
	}
	return &mcpauth.TokenInfo{UserID: u.ID, Expiration: t.ExpiresAt, Extra: map[string]any{"email": u.Email}}, nil
}

func (s *Server) SetSession(w http.ResponseWriter, u store.User) {
	v, err := s.Signer.Sign("session", session{UserID: u.ID, Email: u.Email}, s.SessionTTL)
	if err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: v, Path: "/", MaxAge: int(s.SessionTTL.Seconds()),
		HttpOnly: true, Secure: s.secure(), SameSite: http.SameSiteLaxMode})
}

// WebUser returns the signed-in web user, if any.
func (s *Server) WebUser(r *http.Request) (store.User, bool) {
	ck, err := r.Cookie(sessionCookie)
	if err != nil {
		return store.User{}, false
	}
	var se session
	if s.Signer.Verify("session", ck.Value, &se) != nil || se.UserID == "" {
		return store.User{}, false
	}
	return store.User{ID: se.UserID, Email: se.Email}, true
}

func (s *Server) metadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.PublicURL,
		"authorization_endpoint":                s.PublicURL + "/oauth/authorize",
		"token_endpoint":                        s.PublicURL + "/oauth/token",
		"registration_endpoint":                 s.PublicURL + "/oauth/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	})
}

// register is Dynamic Client Registration (RFC 7591).
// ponytail: every client is public (PKCE, no secret) and registration is open; add rate limiting if it gets abused.
func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil || len(req.RedirectURIs) == 0 {
		writeJSON(w, http.StatusBadRequest, oauthErr("invalid_client_metadata", "redirect_uris is required"))
		return
	}
	for _, u := range req.RedirectURIs {
		if err := checkRedirectURI(u); err != nil {
			writeJSON(w, http.StatusBadRequest, oauthErr("invalid_redirect_uri", err.Error()))
			return
		}
	}
	c := store.Client{ID: rand.Text(), Name: req.ClientName, RedirectURIs: req.RedirectURIs}
	if err := s.Store.CreateClient(r.Context(), c); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id": c.ID, "client_id_issued_at": time.Now().Unix(), "client_name": c.Name,
		"redirect_uris": c.RedirectURIs, "grant_types": []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"}, "token_endpoint_auth_method": "none",
	})
}

// checkRedirectURI allows https, http on loopback only (RFC 8252), and
// private-use schemes such as cursor://. It refuses fragments and script-capable schemes.
func checkRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return errors.New("redirect_uri must be an absolute URI")
	}
	if u.Fragment != "" {
		return errors.New("redirect_uri must not have a fragment")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		if u.Host == "" {
			return errors.New("redirect_uri needs a host")
		}
	case "http":
		if h := u.Hostname(); h != "localhost" && h != "127.0.0.1" && h != "::1" {
			return errors.New("http redirect_uri is only allowed on loopback")
		}
	case "javascript", "data", "file", "vbscript":
		return errors.New("redirect_uri scheme not allowed")
	}
	return nil
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	client, err := s.Store.GetClient(r.Context(), q.Get("client_id"))
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "Unknown client. Remove and re-add valetkey in your client.", http.StatusBadRequest)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	redirect := q.Get("redirect_uri")
	if !slices.Contains(client.RedirectURIs, redirect) {
		http.Error(w, "redirect_uri is not registered for this client", http.StatusBadRequest)
		return
	}
	if q.Get("response_type") != "code" {
		redirectWith(w, r, redirect, url.Values{"error": {"unsupported_response_type"}, "state": {q.Get("state")}})
		return
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		redirectWith(w, r, redirect, url.Values{"error": {"invalid_request"},
			"error_description": {"PKCE with S256 is required"}, "state": {q.Get("state")}})
		return
	}
	s.toIdP(w, r, pending{Kind: "mcp", ClientID: client.ID, RedirectURI: redirect,
		Challenge: q.Get("code_challenge"), State: q.Get("state")})
}

func (s *Server) toIdP(w http.ResponseWriter, r *http.Request, p pending) {
	p.Nonce = rand.Text()
	state, err := s.Signer.Sign("idp-state", p, codeTTL)
	if err != nil {
		s.fail(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: nonceCookie, Value: p.Nonce, Path: "/oauth/oidc/callback",
		MaxAge: int(codeTTL.Seconds()), HttpOnly: true, Secure: s.secure(), SameSite: http.SameSiteLaxMode})
	var opts []oauth2.AuthCodeOption
	if s.IdP.Issuer == googleIssuer {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "select_account"))
	}
	http.Redirect(w, r, s.IdP.Config.AuthCodeURL(state, opts...), http.StatusFound)
}

func (s *Server) idpCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var p pending
	if err := s.Signer.Verify("idp-state", q.Get("state"), &p); err != nil {
		http.Error(w, "Sign-in expired or invalid. Start again.", http.StatusBadRequest)
		return
	}
	ck, err := r.Cookie(nonceCookie)
	if err != nil || subtle.ConstantTimeCompare([]byte(ck.Value), []byte(p.Nonce)) != 1 {
		http.Error(w, "Sign-in was started in another browser. Start again.", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: nonceCookie, Path: "/oauth/oidc/callback", MaxAge: -1})
	if e := q.Get("error"); e != "" {
		http.Error(w, "Sign-in failed: "+e, http.StatusBadRequest)
		return
	}
	email, err := s.IdP.Email(r.Context(), q.Get("code"))
	if err != nil {
		s.Log.Warn("sign-in rejected", "err", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	user, err := s.Store.UpsertUser(r.Context(), email)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.SetSession(w, user)
	if p.Kind == "web" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	name := "An unnamed client"
	if c, err := s.Store.GetClient(r.Context(), p.ClientID); err == nil && c.Name != "" {
		name = c.Name
	}
	cp := consentPayload{UserID: user.ID, ClientID: p.ClientID, ClientName: name,
		RedirectURI: p.RedirectURI, Challenge: p.Challenge, State: p.State}
	signed, err := s.Signer.Sign("consent", cp, codeTTL)
	if err != nil {
		s.fail(w, err)
		return
	}
	host := p.RedirectURI
	if u, err := url.Parse(p.RedirectURI); err == nil {
		host = u.Scheme + "://" + u.Host
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	consentTmpl.Execute(w, map[string]string{"Name": name, "Email": user.Email, "Host": host, "Consent": signed})
}

type consentPayload struct {
	UserID      string `json:"u"`
	ClientID    string `json:"c"`
	ClientName  string `json:"n"`
	RedirectURI string `json:"r"`
	Challenge   string `json:"p"`
	State       string `json:"s"`
}

var consentTmpl = template.Must(template.New("consent").Funcs(template.FuncMap{"head": func() template.HTML { return ui.Head }}).Parse(`<!doctype html>
<html lang="en"><head>
{{head}}
<title>Allow access · valetkey</title>
</head>
<body><div class="wrap">
<div class="bar">
  <span class="mark">valetkey</span>
  <button class="btn small" type="button" data-theme-toggle hidden>Switch to dark</button>
</div>
<main>
<h1>Let {{.Name}} use valetkey?</h1>
<p class="lead">It will act as <strong>{{.Email}}</strong>, with the tools you have connected here. Every call it makes shows up on your activity page.</p>
<div class="card">
<p>If you allow it, valetkey sends you back to:</p>
<pre>{{.Host}}</pre>
<form method="post" action="/oauth/consent" class="actions">
<input type="hidden" name="consent" value="{{.Consent}}">
<button class="btn primary" type="submit" name="action" value="approve">Approve</button>
<button class="btn" type="submit" name="action" value="deny">Deny</button>
</form>
<p class="muted">Did not start this yourself? Choose Deny.</p>
</div>
</main></div></body></html>`))

// consent finishes the MCP flow once the signed-in user approves or denies.
func (s *Server) consent(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != s.PublicURL {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var cp consentPayload
	if err := s.Signer.Verify("consent", r.FormValue("consent"), &cp); err != nil {
		http.Error(w, "Consent expired or invalid. Start again.", http.StatusBadRequest)
		return
	}
	if u, ok := s.WebUser(r); !ok || u.ID != cp.UserID {
		http.Error(w, "Consent belongs to another session. Start again.", http.StatusBadRequest)
		return
	}
	if r.FormValue("action") != "approve" {
		redirectWith(w, r, cp.RedirectURI, url.Values{"error": {"access_denied"}, "state": {cp.State}})
		return
	}
	code := rand.Text()
	if err := s.Store.SaveCode(r.Context(), store.Code{Hash: hash(code), ClientID: cp.ClientID, UserID: cp.UserID,
		RedirectURI: cp.RedirectURI, Challenge: cp.Challenge, ExpiresAt: time.Now().Add(codeTTL)}); err != nil {
		s.fail(w, err)
		return
	}
	redirectWith(w, r, cp.RedirectURI, url.Values{"code": {code}, "state": {cp.State}})
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, oauthErr("invalid_request", "malformed form"))
		return
	}
	f := r.PostForm
	var clientID, userID string
	refreshExp := time.Now().Add(s.RefreshTTL)
	switch f.Get("grant_type") {
	case "authorization_code":
		c, err := s.Store.TakeCode(r.Context(), hash(f.Get("code")))
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.fail(w, err)
			return
		}
		if err != nil || time.Now().After(c.ExpiresAt) || c.ClientID != f.Get("client_id") ||
			c.RedirectURI != f.Get("redirect_uri") || !pkceOK(f.Get("code_verifier"), c.Challenge) {
			writeJSON(w, http.StatusBadRequest, oauthErr("invalid_grant", "invalid, expired or already used code"))
			return
		}
		clientID, userID = c.ClientID, c.UserID
	case "refresh_token":
		t, err := s.Store.TakeToken(r.Context(), hash(f.Get("refresh_token")), "refresh")
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.fail(w, err)
			return
		}
		if err != nil || time.Now().After(t.ExpiresAt) || t.ClientID != f.Get("client_id") {
			writeJSON(w, http.StatusBadRequest, oauthErr("invalid_grant", "invalid or expired refresh token"))
			return
		}
		clientID, userID = t.ClientID, t.UserID
		refreshExp = t.ExpiresAt // rotation never extends the lifetime
	default:
		writeJSON(w, http.StatusBadRequest, oauthErr("unsupported_grant_type", ""))
		return
	}
	access, refresh, now := rand.Text(), rand.Text(), time.Now()
	for _, t := range []store.Token{
		{Hash: hash(access), Kind: "access", ClientID: clientID, UserID: userID, ExpiresAt: now.Add(s.AccessTTL)},
		{Hash: hash(refresh), Kind: "refresh", ClientID: clientID, UserID: userID, ExpiresAt: refreshExp},
	} {
		if err := s.Store.SaveToken(r.Context(), t); err != nil {
			s.fail(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": access, "token_type": "Bearer",
		"expires_in": int(s.AccessTTL.Seconds()), "refresh_token": refresh})
}

func pkceOK(verifier, challenge string) bool {
	if verifier == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
}

func hash(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

func (s *Server) secure() bool { return strings.HasPrefix(s.PublicURL, "https://") }

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.Log.Error("auth request failed", "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// redirectWith adds params to a registered (already validated) redirect URI.
func redirectWith(w http.ResponseWriter, r *http.Request, base string, params url.Values) {
	u, _ := url.Parse(base)
	q := u.Query()
	for k, v := range params {
		if len(v) > 0 && v[0] != "" {
			q[k] = v
		}
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func oauthErr(code, desc string) map[string]string {
	m := map[string]string{"error": code}
	if desc != "" {
		m["error_description"] = desc
	}
	return m
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
