package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// fakeIdP serves OIDC discovery and a token endpoint whose ID token carries
// claims(issuer). discoveredIssuer overrides the issuer in discovery when set.
func fakeIdP(t *testing.T, claims func(iss string) map[string]any, discoveredIssuer string) *httptest.Server {
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			iss := ts.URL
			if discoveredIssuer != "" {
				iss = discoveredIssuer
			}
			json.NewEncoder(w).Encode(map[string]string{"issuer": iss, "authorization_endpoint": ts.URL + "/auth", "token_endpoint": ts.URL + "/token"})
		case "/token":
			b, _ := json.Marshal(claims(ts.URL))
			json.NewEncoder(w).Encode(map[string]any{"access_token": "a", "token_type": "Bearer", "expires_in": 3600,
				"id_token": "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func idClaims(email string, extra map[string]any) func(string) map[string]any {
	return func(iss string) map[string]any {
		c := map[string]any{"iss": iss, "aud": "cid", "email": email, "email_verified": true}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}
}

func oidcFor(t *testing.T, ts *httptest.Server, issuer string) *OIDC {
	return &OIDC{Issuer: issuer, AllowedDomains: []string{"example.com"}, AllowedEmails: []string{"contractor@gmail.com"},
		Config: &oauth2.Config{ClientID: "cid", ClientSecret: "cs", Endpoint: oauth2.Endpoint{AuthURL: ts.URL + "/auth", TokenURL: ts.URL + "/token"}}}
}

func TestOIDCEmail(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		claims func(string) map[string]any
		issuer string // empty: the fake's own URL
		trust  bool
		want   string // empty: refused
	}{
		"allowed domain, lowercased": {claims: idClaims("Alice@Example.COM", nil), want: "alice@example.com"},
		"allowed email":              {claims: idClaims("contractor@gmail.com", nil), want: "contractor@gmail.com"},
		"unlisted":                   {claims: idClaims("eve@other.com", nil)},
		"lookalike domain":           {claims: idClaims("eve@notexample.com", nil)},
		"unverified":                 {claims: idClaims("a@example.com", map[string]any{"email_verified": false})},
		"missing verified": {claims: func(iss string) map[string]any {
			return map[string]any{"iss": iss, "aud": "cid", "email": "a@example.com"}
		}},
		"missing verified, trusted": {claims: func(iss string) map[string]any {
			return map[string]any{"iss": iss, "aud": "cid", "email": "a@example.com"}
		}, trust: true, want: "a@example.com"},
		"verified as string": {claims: idClaims("a@example.com", map[string]any{"email_verified": "true"}), want: "a@example.com"},
		"wrong iss":          {claims: func(string) map[string]any { return idClaims("a@example.com", nil)("https://evil.example") }},
		"wrong aud":          {claims: idClaims("a@example.com", map[string]any{"aud": "other"})},
		"aud array":          {claims: idClaims("a@example.com", map[string]any{"aud": []string{"other", "cid"}}), want: "a@example.com"},
		"no email":           {claims: idClaims("", nil)},
		"google workspace": {issuer: googleIssuer, claims: func(string) map[string]any {
			return idClaims("a@example.com", map[string]any{"hd": "example.com"})(googleIssuer)
		}, want: "a@example.com"},
		"google consumer, company address": {issuer: googleIssuer, claims: func(string) map[string]any { return idClaims("a@example.com", nil)(googleIssuer) }},
		"google consumer, allowed email":   {issuer: googleIssuer, claims: func(string) map[string]any { return idClaims("contractor@gmail.com", nil)(googleIssuer) }, want: "contractor@gmail.com"},
		"google iss without scheme": {issuer: googleIssuer, claims: func(string) map[string]any {
			return idClaims("a@example.com", map[string]any{"hd": "example.com"})("accounts.google.com")
		}, want: "a@example.com"},
		"other issuer without scheme": {claims: func(iss string) map[string]any {
			return idClaims("a@example.com", nil)(strings.TrimPrefix(iss, "http://"))
		}},
	} {
		t.Run(name, func(t *testing.T) {
			ts := fakeIdP(t, tc.claims, "")
			iss := tc.issuer
			if iss == "" {
				iss = ts.URL
			}
			o := oidcFor(t, ts, iss)
			o.TrustUnverifiedEmail = tc.trust
			got, err := o.Email(ctx, "code")
			if tc.want == "" {
				if err == nil {
					t.Fatalf("accepted %q", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("Email = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestDiscover(t *testing.T) {
	ts := fakeIdP(t, idClaims("a@example.com", nil), "")
	ep, err := Discover(context.Background(), ts.URL)
	if err != nil || ep.TokenURL != ts.URL+"/token" || ep.AuthURL != ts.URL+"/auth" {
		t.Fatalf("Discover = %+v, %v", ep, err)
	}
	bad := fakeIdP(t, idClaims("a@example.com", nil), "https://someone-else.example")
	if _, err := Discover(context.Background(), bad.URL); err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("issuer mismatch accepted: %v", err)
	}
}

func TestDiscoverTimesOut(t *testing.T) {
	done := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-done }))
	t.Cleanup(ts.Close)
	t.Cleanup(func() { close(done) })
	old := discoveryClient.Timeout
	discoveryClient.Timeout = 100 * time.Millisecond
	t.Cleanup(func() { discoveryClient.Timeout = old })
	start := time.Now()
	if _, err := Discover(context.Background(), ts.URL); err == nil {
		t.Fatal("Discover succeeded against a server that never answers")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Discover took %s", d)
	}
}
